# Deploy: Infraestructura Resiliente

Configuraciones de infraestructura para despliegue en producción.

## Archivos

| Archivo | Destino en Server | Descripción |
|---------|-------------------|-------------|
| `nginx-backup_manager.conf` | `/etc/nginx/sites-available/backup_manager` | Config Nginx con HTTP health exception |
| `backup_manager.service` | `/etc/systemd/system/backup_manager.service` | Unit Gunicorn con bind absoluto |
| `cert-watcher.sh` | `/opt/scripts/cert-watcher.sh` | Script gestión de certs |
| `cert-watcher.service` | `/etc/systemd/system/cert-watcher.service` | Service para el watcher |
| `cert-watcher.timer` | `/etc/systemd/system/cert-watcher.timer` | Timer cada 6 horas |

## Instalación

```bash
# 1. Copiar configs
cp deploy/nginx-backup_manager.conf /etc/nginx/sites-available/backup_manager
ln -sf /etc/nginx/sites-available/backup_manager /etc/nginx/sites-enabled/

cp deploy/backup_manager.service /etc/systemd/system/
cp deploy/cert-watcher.service /etc/systemd/system/
cp deploy/cert-watcher.timer /etc/systemd/system/

mkdir -p /opt/scripts
cp deploy/cert-watcher.sh /opt/scripts/
chmod +x /opt/scripts/cert-watcher.sh

# 2. Crear directorios necesarios
mkdir -p /var/lib/cert-watcher
mkdir -p /var/log/backup_manager

# 3. Reload systemd
systemctl daemon-reload

# 4. Habilitar servicios
systemctl enable backup_manager
systemctl enable cert-watcher.timer

# 5. Verificar Nginx
nginx -t

# 6. Aplicar
systemctl restart backup_manager
systemctl reload nginx
systemctl start cert-watcher.timer
```

## Verificación

```bash
# Health por HTTP (debe ser 200, no 301)
curl -sS -o /dev/null -w "%{http_code}" http://localhost/api/health
# Esperado: 200

# Health por HTTPS (si cert válido)
curl -sS -o /dev/null -w "%{http_code}" https://localhost/api/health
# Esperado: 200

# Socket existe
ls -la /opt/backup_system/backup_manager.sock
# Esperado: srw-rw-rw- root root

# Cert watcher timer activo
systemctl status cert-watcher.timer
# Esperado: active

# Días hasta expiración del cert
openssl x509 -in /etc/letsencrypt/live/backupmanager.testwilnet.com.ar/fullchain.pem -noout -enddate
```

## Root Causes Resueltos

| Problema | Causa | Solución |
|----------|-------|----------|
| HTTP 301 rompe health checks | Redirect incondicional | Location específica sin redirect |
| 502 Bad Gateway | Socket path relativo | Bind absoluto en systemd |
| Cert lock stuck | Proceso zombie | Cleanup en cert-watcher |
| Renovación silenciosa | Solo cron de certbot | Wrapper con validación y alertas |

## Arquitectura

```
                    ┌─────────────────┐
                    │    Internet     │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
        HTTP :80                      HTTPS :443
              │                             │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │ /api/health     │           │ TLS Termination │
    │ /.well-known/   │           │ (Let's Encrypt) │
    │ → proxy to app  │           │ → proxy to app  │
    │                 │           │                 │
    │ /* → 301 HTTPS  │           └────────┬────────┘
    └────────┬────────┘                    │
             │                             │
             └──────────────┬──────────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │   Nginx Upstream    │
                 │   (Unix Socket)     │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │     Gunicorn        │
                 │   backup_manager    │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │   Flask App         │
                 │   web_app.py        │
                 └─────────────────────┘
```
