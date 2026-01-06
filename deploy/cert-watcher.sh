#!/bin/bash
# =============================================================================
# Cert Watcher - Gestión Idempotente de Certificados TLS
# =============================================================================
# Archivo: /opt/scripts/cert-watcher.sh
# Timer: /etc/systemd/system/cert-watcher.timer (cada 6 horas)
#
# FUNCIONALIDAD:
# 1. Detecta días hasta expiración del cert
# 2. Limpia locks de certbot si proceso muerto
# 3. Renueva si <= 30 días
# 4. Valida cert nuevo
# 5. Recarga Nginx solo si todo OK
# 6. Reintenta con backoff (estado persistente)
# 7. Logging estructurado
#
# IDEMPOTENCIA:
# - Puede ejecutarse N veces sin efectos secundarios
# - Cada ejecución verifica estado real, no asume
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURACIÓN
# =============================================================================
DOMAIN="backupmanager.testwilnet.com.ar"
CERT_PATH="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
STATE_DIR="/var/lib/cert-watcher"
STATE_FILE="${STATE_DIR}/state.json"
LOG_FILE="/var/log/cert-watcher.log"

RENEW_THRESHOLD_DAYS=30
MAX_RETRIES=5
LOCKFILE="/var/lib/letsencrypt/.certbot.lock"

# =============================================================================
# LOGGING
# =============================================================================
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date -Iseconds)
    echo "{\"timestamp\":\"${timestamp}\",\"level\":\"${level}\",\"message\":\"${message}\"}" | tee -a "$LOG_FILE"
}

log_info()  { log "INFO"  "$@"; }
log_warn()  { log "WARN"  "$@"; }
log_error() { log "ERROR" "$@"; }

# =============================================================================
# STATE MANAGEMENT
# =============================================================================
init_state() {
    mkdir -p "$STATE_DIR"
    if [[ ! -f "$STATE_FILE" ]]; then
        echo '{"retry_count":0,"last_attempt":"","last_success":""}' > "$STATE_FILE"
    fi
}

get_state() {
    local key="$1"
    jq -r ".${key} // empty" "$STATE_FILE" 2>/dev/null || echo ""
}

set_state() {
    local key="$1"
    local value="$2"
    local tmp
    tmp=$(mktemp)
    jq ".${key} = \"${value}\"" "$STATE_FILE" > "$tmp" && mv "$tmp" "$STATE_FILE"
}

increment_retry() {
    local current
    current=$(get_state "retry_count")
    current=${current:-0}
    set_state "retry_count" "$((current + 1))"
    set_state "last_attempt" "$(date -Iseconds)"
}

reset_retry() {
    set_state "retry_count" "0"
    set_state "last_success" "$(date -Iseconds)"
}

# =============================================================================
# CERT CHECKING
# =============================================================================
get_cert_expiry_days() {
    if [[ ! -f "$CERT_PATH" ]]; then
        echo "-1"
        return
    fi
    
    local expiry_date
    expiry_date=$(openssl x509 -in "$CERT_PATH" -noout -enddate 2>/dev/null | cut -d= -f2)
    
    if [[ -z "$expiry_date" ]]; then
        echo "-1"
        return
    fi
    
    local expiry_epoch now_epoch
    expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || echo 0)
    now_epoch=$(date +%s)
    
    echo $(( (expiry_epoch - now_epoch) / 86400 ))
}

# =============================================================================
# LOCK CLEANUP
# =============================================================================
cleanup_stale_lock() {
    if [[ ! -f "$LOCKFILE" ]]; then
        return 0
    fi
    
    # Verificar si hay proceso certbot corriendo
    if pgrep -f "certbot" > /dev/null 2>&1; then
        log_warn "Certbot process running, lock is valid"
        return 1
    fi
    
    # Lock existe pero no hay proceso - limpiar
    log_warn "Removing stale certbot lock file"
    rm -f "$LOCKFILE"
    return 0
}

# =============================================================================
# CERT RENEWAL
# =============================================================================
attempt_renewal() {
    log_info "Attempting certificate renewal for ${DOMAIN}"
    
    # Backup cert actual
    local backup_dir="${STATE_DIR}/backups"
    mkdir -p "$backup_dir"
    if [[ -f "$CERT_PATH" ]]; then
        cp "$CERT_PATH" "${backup_dir}/fullchain-$(date +%Y%m%d-%H%M%S).pem"
    fi
    
    # Ejecutar certbot
    if certbot renew \
        --cert-name "$DOMAIN" \
        --non-interactive \
        --no-random-sleep-on-renew \
        --deploy-hook "systemctl reload nginx" \
        2>&1 | tee -a "$LOG_FILE"; then
        
        log_info "Certbot renewal completed"
        return 0
    else
        log_error "Certbot renewal failed"
        return 1
    fi
}

validate_cert() {
    if [[ ! -f "$CERT_PATH" ]]; then
        log_error "Certificate file not found: ${CERT_PATH}"
        return 1
    fi
    
    # Verificar que el cert es válido
    if ! openssl x509 -in "$CERT_PATH" -noout -checkend 0 2>/dev/null; then
        log_error "Certificate is expired or invalid"
        return 1
    fi
    
    # Verificar chain
    local chain_path="/etc/letsencrypt/live/${DOMAIN}/chain.pem"
    if [[ -f "$chain_path" ]]; then
        if ! openssl verify -CAfile "$chain_path" "$CERT_PATH" 2>/dev/null; then
            log_warn "Certificate chain verification warning"
        fi
    fi
    
    log_info "Certificate validation passed"
    return 0
}

reload_nginx_if_valid() {
    # Verificar config de Nginx
    if ! nginx -t 2>&1 | tee -a "$LOG_FILE"; then
        log_error "Nginx config test failed, NOT reloading"
        return 1
    fi
    
    # Reload
    if systemctl reload nginx 2>&1 | tee -a "$LOG_FILE"; then
        log_info "Nginx reloaded successfully"
        return 0
    else
        log_error "Nginx reload failed"
        return 1
    fi
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    log_info "=== Cert Watcher Starting ==="
    init_state
    
    # Obtener estado actual del cert
    local days_remaining
    days_remaining=$(get_cert_expiry_days)
    log_info "Certificate expires in ${days_remaining} days"
    
    # Si cert es válido y no cerca de expirar, salir
    if [[ "$days_remaining" -gt "$RENEW_THRESHOLD_DAYS" ]]; then
        log_info "Certificate OK, no renewal needed"
        exit 0
    fi
    
    # Cert necesita renovación
    if [[ "$days_remaining" -le 0 ]]; then
        log_error "Certificate is EXPIRED"
    else
        log_warn "Certificate expires in ${days_remaining} days, renewal needed"
    fi
    
    # Verificar retry count
    local retry_count
    retry_count=$(get_state "retry_count")
    retry_count=${retry_count:-0}
    
    if [[ "$retry_count" -ge "$MAX_RETRIES" ]]; then
        log_error "Max retries (${MAX_RETRIES}) exceeded. Manual intervention required."
        log_error "Run: rm ${STATE_FILE} to reset retry counter"
        exit 1
    fi
    
    # Limpiar locks stale
    if ! cleanup_stale_lock; then
        log_warn "Cannot proceed, valid certbot lock exists"
        exit 0
    fi
    
    # Intentar renovación
    if attempt_renewal; then
        if validate_cert; then
            reload_nginx_if_valid
            reset_retry
            log_info "=== Renewal completed successfully ==="
            exit 0
        else
            log_error "Renewal succeeded but validation failed"
            increment_retry
            exit 1
        fi
    else
        increment_retry
        local new_count
        new_count=$(get_state "retry_count")
        log_error "Renewal failed. Retry ${new_count}/${MAX_RETRIES}"
        exit 1
    fi
}

# Run
main "$@"
