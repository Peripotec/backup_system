from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, abort, Response, session
import os
import shutil
import yaml
import json
import threading
import subprocess
import secrets
import hashlib
import time
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
from settings import BACKUP_ROOT_DIR, INVENTORY_FILE, DB_FILE, REPO_DIR, ARCHIVE_DIR
from core.db_manager import DBManager
from core.config_manager import get_config_manager
from core.logger import log

app = Flask(__name__, static_folder='static', static_url_path='/static')

# ===========================================
# SECURITY CONFIGURATION
# ===========================================

# Persistent secret key (stored in file so sessions survive restarts)
SECRET_KEY_FILE = os.path.join(os.path.dirname(DB_FILE), '.flask_secret')
def get_or_create_secret_key():
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, 'r') as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    try:
        with open(SECRET_KEY_FILE, 'w') as f:
            f.write(key)
        os.chmod(SECRET_KEY_FILE, 0o600)  # Only owner can read
    except Exception:
        pass  # Fallback to in-memory key
    return key

app.secret_key = get_or_create_secret_key()

# Session configuration
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_COOKIE_HTTPONLY'] = True      # Prevent JS access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'     # CSRF protection (Strict when SSL ready)
app.config['SESSION_COOKIE_SECURE'] = False       # Set True when HTTPS is enabled
app.config['SESSION_COOKIE_NAME'] = 'backup_session'

# Rate limiting storage (in-memory, resets on restart)
login_attempts = defaultdict(lambda: {'count': 0, 'blocked_until': None})

# ===========================================
# VENDOR FOLDER MAPPING
# ===========================================
# The backup engine creates folders using the Python class name lowercased.
# This maps inventory vendor values to physical folder names.
VENDOR_FOLDER_MAP = {
    'hp': 'hp',
    'huawei': 'huawei', 
    'zte_olt': 'zteolt',  # Class ZteOlt -> folder 'zteolt'
    'cisco': 'cisco',
    'mikrotik': 'mikrotik',
    'juniper': 'juniper',
    'fortinet': 'fortinet',
}

def normalize_vendor_folder(vendor):
    """
    Convert inventory vendor value to physical folder name.
    The backup engine uses ClassName.lower() for folders.
    Examples:
        'zte_olt' -> 'zteolt' (class ZteOlt)
        'huawei' -> 'huawei' (class Huawei)
    """
    if not vendor:
        return ''
    vendor_lower = vendor.lower()
    if vendor_lower in VENDOR_FOLDER_MAP:
        return VENDOR_FOLDER_MAP[vendor_lower]
    # Fallback: remove underscores and lowercase (matches class naming convention)
    return vendor_lower.replace('_', '')

MAX_LOGIN_ATTEMPTS = 5
LOGIN_BLOCK_DURATION = 300  # 5 minutes

# ===========================================
# AUDIT HELPER
# ===========================================

# Event categories for audit log
AUDIT_CATEGORIES = {
    'auth_login': 'auth',
    'auth_logout': 'auth',
    'auth_failed': 'auth',
    'token_create': 'auth',
    'token_delete': 'auth',
    'device_create': 'inventory',
    'device_update': 'inventory',
    'device_delete': 'inventory',
    'device_enable': 'inventory',
    'device_disable': 'inventory',
    'group_create': 'inventory',
    'group_update': 'inventory',
    'group_delete': 'inventory',
    'credential_create': 'vault',
    'credential_update': 'vault',
    'credential_delete': 'vault',
    'user_create': 'users',
    'user_update': 'users',
    'user_delete': 'users',
    'user_role_change': 'users',
    'auth_password_change': 'auth',
    'settings_update': 'config',
    'schedule_update': 'config',
    'email_test': 'config',
    'backup_manual': 'backup',
    'backup_scheduled': 'backup',
    'backup_result': 'backup',
    'backup_error': 'backup',
    'file_view': 'files',
    'file_download': 'files',
    'file_delete': 'files',
    'role_create': 'users',
    'role_update': 'users',
    'role_delete': 'users',
}

def parse_user_agent(ua_string):
    """Parse user agent string to a short Browser/OS format."""
    if not ua_string:
        return None
    
    ua = ua_string.lower()
    
    # Detect browser
    browser = "Unknown"
    if "edg/" in ua or "edge/" in ua:
        browser = "Edge"
    elif "chrome/" in ua and "safari/" in ua:
        browser = "Chrome"
    elif "firefox/" in ua:
        browser = "Firefox"
    elif "safari/" in ua and "chrome/" not in ua:
        browser = "Safari"
    elif "opera" in ua or "opr/" in ua:
        browser = "Opera"
    elif "msie" in ua or "trident/" in ua:
        browser = "IE"
    
    # Detect OS
    os = "Unknown"
    if "windows" in ua:
        os = "Windows"
    elif "mac os" in ua or "macintosh" in ua:
        os = "macOS"
    elif "linux" in ua:
        os = "Linux"
    elif "android" in ua:
        os = "Android"
    elif "iphone" in ua or "ipad" in ua:
        os = "iOS"
    
    return f"{browser}/{os}"

def get_real_ip():
    """Get real client IP, supporting reverse proxy headers."""
    if not request:
        return None
    # Check X-Forwarded-For first (Nginx, load balancers)
    xff = request.headers.get('X-Forwarded-For')
    if xff:
        # Take first IP (original client)
        return xff.split(',')[0].strip()
    # Check X-Real-IP (Nginx)
    xri = request.headers.get('X-Real-IP')
    if xri:
        return xri.strip()
    # Fallback to remote_addr
    return request.remote_addr

def log_audit(event_type, entity_type=None, entity_id=None, entity_name=None, details=None):
    """
    Central helper to log audit events.
    Automatically captures user info, IP (supports proxy), and user agent from Flask context.
    """
    try:
        user_id = session.get('user_id')
        username = session.get('username', 'anonymous')
        ip_address = get_real_ip()
        raw_ua = request.headers.get('User-Agent', '') if request else None
        user_agent = parse_user_agent(raw_ua)
        event_category = AUDIT_CATEGORIES.get(event_type, 'other')
        
        # Enhance details with user_agent if not already present
        if details is None:
            details = {}
        if user_agent and 'user_agent' not in details:
            details['user_agent'] = user_agent
        
        db = DBManager()
        db.log_audit_event(
            user_id=user_id,
            username=username,
            event_type=event_type,
            event_category=event_category,
            entity_type=entity_type,
            entity_id=entity_id,
            entity_name=entity_name,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent
        )
    except Exception as e:
        log.error(f"Failed to log audit event {event_type}: {e}")

# ===========================================
# SECURITY MIDDLEWARE
# ===========================================

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # XSS Protection (legacy browsers)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Content Security Policy (basic)
    response.headers['Content-Security-Policy'] = "default-src 'self' https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net"
    return response

def is_ip_blocked(ip):
    """Check if IP is blocked due to too many failed attempts."""
    data = login_attempts[ip]
    if data['blocked_until']:
        if time.time() < data['blocked_until']:
            return True
        # Block expired, reset
        login_attempts[ip] = {'count': 0, 'blocked_until': None}
    return False

def record_failed_login(ip):
    """Record a failed login attempt."""
    login_attempts[ip]['count'] += 1
    if login_attempts[ip]['count'] >= MAX_LOGIN_ATTEMPTS:
        login_attempts[ip]['blocked_until'] = time.time() + LOGIN_BLOCK_DURATION
        log.warning(f"IP {ip} blocked for {LOGIN_BLOCK_DURATION}s due to {MAX_LOGIN_ATTEMPTS} failed login attempts")

def reset_login_attempts(ip):
    """Reset login attempts after successful login."""
    if ip in login_attempts:
        del login_attempts[ip]

# Global state for backup execution
backup_status = {"running": False, "message": "", "progress": 0}

def get_current_user():
    """Get current logged-in user from session."""
    if 'user_id' in session:
        cfg = get_config_manager()
        return cfg.get_user_by_id(session['user_id'])
    return None

def requires_auth(f):
    """Decorator to require authentication via session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            # Check if it's an API request
            if request.path.startswith('/api/'):
                # Check for API token in header
                auth_header = request.headers.get('Authorization', '')
                if auth_header.startswith('Bearer '):
                    token = auth_header[7:]
                    cfg = get_config_manager()
                    token_data = cfg.validate_api_token(token)
                    if token_data:
                        return f(*args, **kwargs)
                return jsonify({"error": "Authentication required"}), 401
            # Redirect to login for web pages
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated

# Role permission defaults (used when user doesn't have explicit permissions)
ROLE_HIERARCHY = ['viewer', 'operator', 'admin', 'superadmin']
ROLE_PERMISSIONS = {
    'viewer': ['view_dashboard', 'view_files', 'view_diff'],
    'operator': ['view_dashboard', 'view_files', 'view_diff', 'run_backup', 'view_inventory'],
    'admin': ['view_dashboard', 'view_files', 'view_diff', 'run_backup', 'view_inventory', 
              'edit_inventory', 'view_vault', 'edit_vault', 'view_settings', 'edit_settings', 'test_email'],
    'superadmin': ['view_dashboard', 'view_files', 'view_diff', 'run_backup', 'view_inventory', 
                   'edit_inventory', 'view_vault', 'edit_vault', 'view_settings', 'edit_settings',
                   'test_email', 'manage_users', 'manage_roles', 'view_logs']
}

# Catálogo de permisos por categoría (source of truth para UI de roles)
PERMISSIONS_CATALOG = {
    'Visualización': [
        {'id': 'view_dashboard', 'label': 'Dashboard', 'description': 'Ver dashboard principal'},
        {'id': 'view_files', 'label': 'Archivos', 'description': 'Ver archivos de backup'},
        {'id': 'view_diff', 'label': 'Comparar versiones', 'description': 'Ver diferencias entre backups'},
        {'id': 'view_inventory', 'label': 'Ver inventario', 'description': 'Ver lista de dispositivos'},
        {'id': 'view_vault', 'label': 'Ver credenciales', 'description': 'Ver vault de credenciales'},
        {'id': 'view_settings', 'label': 'Ver configuración', 'description': 'Ver configuración del sistema'},
        {'id': 'view_logs', 'label': 'Ver auditoría', 'description': 'Ver registro de auditoría del sistema'},
    ],
    'Edición': [
        {'id': 'run_backup', 'label': 'Ejecutar backup', 'description': 'Ejecutar backups manualmente'},
        {'id': 'edit_inventory', 'label': 'Editar inventario', 'description': 'Modificar dispositivos'},
        {'id': 'edit_vault', 'label': 'Editar credenciales', 'description': 'Modificar vault'},
        {'id': 'edit_settings', 'label': 'Editar configuración', 'description': 'Modificar config del sistema'},
    ],
    'Email': [
        {'id': 'test_email', 'label': 'Enviar email de prueba', 'description': 'Usar botón de test en Config → Email'},
    ],
    'Administración': [
        {'id': 'manage_users', 'label': 'Gestionar usuarios', 'description': 'Crear/editar/eliminar usuarios'},
        {'id': 'manage_roles', 'label': 'Gestionar roles', 'description': 'Crear/editar/eliminar roles'},
    ]
}

# Lista plana de todos los permisos válidos (para validación)
ALL_VALID_PERMISSIONS = [p['id'] for cat in PERMISSIONS_CATALOG.values() for p in cat]


def get_effective_permissions(user):
    """
    Get effective permissions for a user from DB.
    Priority: user explicit permissions > role permissions from DB > role defaults (fallback only)
    """
    if not user:
        log.debug("get_effective_permissions: no user provided")
        return []
    
    # 1. Check user's explicit permissions first
    user_perms = user.get('permissions', [])
    if user_perms:
        log.debug(f"get_effective_permissions: using user explicit perms: {user_perms}")
        return user_perms
    
    # 2. Get role permissions from DB (source of truth)
    role_name = user.get('role', 'viewer')
    log.debug(f"get_effective_permissions: user role is '{role_name}'")
    
    cfg = get_config_manager()
    role = cfg.get_role(role_name)
    
    if role:
        # Role exists in DB - use its permissions (even if empty list)
        role_perms = role.get('permissions', [])
        log.debug(f"get_effective_permissions: role '{role_name}' from DB has perms: {role_perms}")
        return role_perms  # Return DB permissions, even if empty
    
    # 3. Fallback to hardcoded defaults ONLY if role doesn't exist in DB
    log.warning(f"Role '{role_name}' not found in DB, using hardcoded fallback defaults")
    default_perms = ROLE_PERMISSIONS.get(role_name, [])
    return default_perms


def has_permission(user_or_role, permission):
    """
    Check if user has a specific permission.
    Queries role permissions from DB, not from hardcoded defaults.
    """
    if isinstance(user_or_role, dict):
        # User dict - get effective permissions
        perms = get_effective_permissions(user_or_role)
        result = permission in perms
        log.debug(f"has_permission: checking '{permission}' in perms - result: {result}")
        return result
    else:
        # Role string - get from DB
        cfg = get_config_manager()
        role = cfg.get_role(user_or_role)
        if role and role.get('permissions'):
            return permission in role['permissions']
        # Fallback to defaults
        return permission in ROLE_PERMISSIONS.get(user_or_role, [])

def requires_role(*roles):
    """Decorator to require specific role(s)."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user or user.get('role') not in roles:
                if request.path.startswith('/api/'):
                    return jsonify({"error": "Permisos insuficientes"}), 403
                # Redirect to dashboard with access denied
                return redirect(url_for('access_denied'))
            return f(*args, **kwargs)
        return decorated
    return decorator

def requires_permission(permission):
    """Decorator to require specific permission."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user or not has_permission(user, permission):
                if request.path.startswith('/api/'):
                    return jsonify({"error": "Permisos insuficientes"}), 403
                return redirect(url_for('access_denied'))
            return f(*args, **kwargs)
        return decorated
    return decorator

def get_db():
    return DBManager(DB_FILE)

@app.context_processor
def inject_user():
    """Inject current user and permission helpers into all templates."""
    user = get_current_user()
    return {
        'current_user': user,
        'session': session,
        'has_permission': lambda perm: has_permission(user, perm) if user else False,
        'ROLE_PERMISSIONS': ROLE_PERMISSIONS
    }

@app.route('/access-denied')
@requires_auth
def access_denied():
    return render_template('access_denied.html'), 403


# ==========================
# HEALTH CHECK (NOC Monitoring)
# ==========================

@app.route('/api/health', strict_slashes=False)
def health_check():
    """
    Health check endpoint for NOC monitoring and load balancers.
    No authentication required for external monitoring tools.
    """
    from datetime import datetime
    import os
    
    checks = {'app': 'ok', 'timestamp': datetime.now().isoformat()}
    all_ok = True
    
    # Check database connection
    try:
        cfg = get_config_manager()
        cfg.get_setting('smtp_enabled')  # Simple query to verify DB
        checks['database'] = 'ok'
    except Exception:
        checks['database'] = 'error'
        all_ok = False
    
    # Check inventory file exists
    try:
        if os.path.exists(INVENTORY_FILE):
            checks['inventory'] = 'ok'
        else:
            checks['inventory'] = 'missing'
            all_ok = False
    except Exception:
        checks['inventory'] = 'error'
        all_ok = False
    
    status_code = 200 if all_ok else 503
    return jsonify(checks), status_code


# ==========================
# GLOBAL SEARCH API
# ==========================

@app.route('/api/search')
@requires_auth
def api_global_search():
    """
    Global search across devices.
    Returns up to 10 results matching the query.
    """
    query = request.args.get('q', '').strip().lower()
    if not query or len(query) < 2:
        return jsonify({'results': []})
    
    inv = load_inventory()
    results = []
    
    for group in inv.get('groups', []):
        group_name = group.get('name', '')
        vendor = group.get('vendor', '')
        
        for device in group.get('devices', []):
            sysname = device.get('sysname', device.get('hostname', ''))
            nombre = device.get('nombre', device.get('name', sysname))
            ip = device.get('ip', '')
            localidad = device.get('localidad', '')
            tipo = device.get('tipo', '')
            
            # Search in multiple fields
            searchable = f"{sysname} {nombre} {ip} {localidad} {tipo} {group_name} {vendor}".lower()
            
            if query in searchable:
                results.append({
                    'sysname': sysname,
                    'nombre': nombre,
                    'ip': ip,
                    'grupo': group_name,
                    'vendor': vendor,
                    'vendor_folder': normalize_vendor_folder(vendor),  # Physical folder name
                    'tipo': tipo,
                    'localidad': localidad
                })
                
                # Limit results
                if len(results) >= 10:
                    break
        
        if len(results) >= 10:
            break
    
    return jsonify({'results': results, 'total': len(results)})


# ==========================
# LOGIN / LOGOUT
# ==========================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    client_ip = request.remote_addr
    error = None
    
    # Check if IP is blocked
    if is_ip_blocked(client_ip):
        remaining = int(login_attempts[client_ip]['blocked_until'] - time.time())
        error = f"Demasiados intentos fallidos. Intenta de nuevo en {remaining} segundos."
        return render_template('login.html', error=error)
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'
        
        cfg = get_config_manager()
        user = cfg.authenticate_user(username, password)
        
        if user:
            # Successful login - reset attempts
            reset_login_attempts(client_ip)
            
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            
            if remember:
                session.permanent = True
            
            log.info(f"User logged in: {username} from {client_ip}")
            log_audit('auth_login', entity_type='user', entity_id=str(user['id']), entity_name=username)
            next_url = request.args.get('next', '/')
            return redirect(next_url)
        else:
            # Failed login - record attempt
            record_failed_login(client_ip)
            attempts_left = MAX_LOGIN_ATTEMPTS - login_attempts[client_ip]['count']
            if attempts_left > 0:
                error = f"Usuario o contraseña incorrectos. ({attempts_left} intentos restantes)"
            else:
                error = f"Cuenta bloqueada por {LOGIN_BLOCK_DURATION // 60} minutos."
            log.warning(f"Failed login attempt for: {username} from {client_ip}")
            log_audit('auth_failed', entity_type='user', entity_name=username, details={'reason': 'invalid_credentials'})
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
    user_id = session.get('user_id')
    log_audit('auth_logout', entity_type='user', entity_id=str(user_id) if user_id else None, entity_name=username)
    session.clear()
    log.info(f"User logged out: {username}")
    return redirect(url_for('login'))

# ==========================
# DASHBOARD
# ==========================


@app.route('/')
@requires_auth
def index():
    db = get_db()
    stats = db.get_stats_24h()
    jobs = db.get_recent_jobs(50)
    inv = load_inventory()
    
    try:
        total, used, free = shutil.disk_usage(BACKUP_ROOT_DIR)
        disk_info = {
            "percent": round((used / total) * 100, 1),
            "free_gb": round(free / (1024**3), 2),
            "total_gb": round(total / (1024**3), 2)
        }
    except Exception:
        disk_info = {"percent": 0, "free_gb": 0, "total_gb": 0}

    return render_template('dashboard.html', stats=stats, jobs=jobs, disk=disk_info, backup_status=backup_status, inventory=inv)

# ==========================
# DIFF / HISTORIAL
# ==========================

@app.route('/diff')
@app.route('/history')
@requires_auth
@requires_permission('view_diff')
def diff_index():
    """Show historial index page with all devices."""
    inv = load_inventory()
    devices = []
    for group in inv.get('groups', []):
        for device in group.get('devices', []):
            devices.append({
                'hostname': device.get('hostname'),
                'ip': device.get('ip'),
                'vendor': group.get('vendor'),
                'group': group.get('name')
            })
    return render_template('historial_index.html', devices=devices)

@app.route('/diff/<vendor>/<hostname>')
@requires_auth
@requires_permission('view_diff')
def diff_view(vendor, hostname):
    """Show diff view for specific device."""
    return render_template('diff.html', vendor=vendor, hostname=hostname)

# ==========================
# INVENTORY PAGES
# ==========================

@app.route('/inventory')
@requires_auth
@requires_permission('view_inventory')
def inventory_page():
    """Redirect to devices by default."""
    return redirect(url_for('inventory_devices'))

@app.route('/inventory/devices')
@requires_auth
@requires_permission('view_inventory')
def inventory_devices():
    """Show devices management page."""
    with open(INVENTORY_FILE, 'r', encoding='utf-8') as f:
        content = f.read()
    inv = load_inventory()
    return render_template('devices.html', inventory=inv, content=content)

@app.route('/inventory/groups')
@requires_auth
@requires_permission('view_inventory')
def inventory_groups():
    """Show groups management page."""
    with open(INVENTORY_FILE, 'r', encoding='utf-8') as f:
        content = f.read()
    inv = load_inventory()
    return render_template('groups.html', inventory=inv, content=content)

# ==========================
# API: BACKUP TRIGGER
# ==========================

# Enhanced status with cancel support and detailed logs
backup_status = {
    "running": False, 
    "cancelled": False,
    "message": "Listo", 
    "progress": 0,
    "current_device": None,
    "completed": [],
    "errors": [],
    "logs": []  # Detailed step-by-step logs
}

def run_backup_async(group=None, devices=None, user_info=None):
    """Run backup in background thread. user_info contains username/ip for audit."""
    global backup_status
    backup_status = {
        "running": True, 
        "cancelled": False,
        "message": "Iniciando backup...", 
        "progress": 5,
        "current_device": None,
        "completed": [],
        "errors": [],
        "logs": [{"type": "info", "msg": "Iniciando proceso de backup..."}]
    }
    
    try:
        from core.engine import BackupEngine
        engine = BackupEngine(dry_run=False)
        
        # Pass status object to engine for real-time updates
        engine.status_callback = update_backup_status
        engine.run(target_group=group, target_devices=devices)
        
        if backup_status["cancelled"]:
            backup_status["message"] = "Cancelado por usuario"
            backup_status["logs"].append({"type": "warning", "msg": "Proceso cancelado por usuario"})
            result = "cancelled"
        else:
            errors = len(backup_status["errors"])
            completed = len(backup_status["completed"])
            backup_status["message"] = f"Completado: {completed} OK, {errors} errores"
            backup_status["progress"] = 100
            backup_status["logs"].append({"type": "success", "msg": f"Finalizado: {completed} exitosos, {errors} fallidos"})
            result = "success" if errors == 0 else "partial"
        
        backup_status["running"] = False
        
        # Log backup_result with user_info passed from request context
        if user_info:
            target = f"{len(devices)} equipos" if devices else (group or "all")
            db = DBManager()
            db.log_audit_event(
                user_id=user_info.get('user_id'),
                username=user_info.get('username', 'unknown'),
                event_type='backup_result',
                event_category='backup',
                entity_type='backup',
                entity_name=target,
                details={
                    'result': result,
                    'completed': len(backup_status["completed"]),
                    'errors': len(backup_status["errors"]),
                    'error_devices': backup_status["errors"][:5]  # First 5 errors
                },
                ip_address=user_info.get('ip_address'),
                user_agent=user_info.get('user_agent')
            )
        
    except Exception as e:
        backup_status["running"] = False
        backup_status["message"] = f"Error: {e}"
        backup_status["logs"].append({"type": "error", "msg": f"Error fatal: {e}"})

def update_backup_status(device_name, status, message=""):
    """Callback for engine to update status in real-time."""
    global backup_status
    
    timestamp = ""
    
    if status == "start":
        backup_status["current_device"] = device_name
        backup_status["message"] = f"Procesando: {device_name}..."
        backup_status["logs"].append({"type": "info", "msg": f"[{device_name}] Iniciando backup..."})
    elif status == "connecting":
        backup_status["logs"].append({"type": "info", "msg": f"[{device_name}] Conectando..."})
    elif status == "login":
        backup_status["logs"].append({"type": "info", "msg": f"[{device_name}] Autenticando..."})
    elif status == "command":
        backup_status["logs"].append({"type": "info", "msg": f"[{device_name}] Ejecutando comando: {message}"})
    elif status == "saving":
        backup_status["logs"].append({"type": "info", "msg": f"[{device_name}] Guardando archivo..."})
    elif status == "git":
        backup_status["logs"].append({"type": "info", "msg": f"[{device_name}] Commit a repositorio..."})
    elif status == "success":
        backup_status["completed"].append({"device": device_name, "msg": message})
        backup_status["logs"].append({"type": "success", "msg": f"[{device_name}] ✓ {message}"})
    elif status == "error":
        backup_status["errors"].append({"device": device_name, "msg": message})
        backup_status["logs"].append({"type": "error", "msg": f"[{device_name}] ✗ {message}"})
    elif status == "log":
        # Generic log message
        backup_status["logs"].append({"type": "info", "msg": f"[{device_name}] {message}"})
    elif status == "debug":
        # Real-time CLI debug output from vendor plugin
        backup_status["logs"].append({"type": "debug", "msg": message})
    
    # Update progress based on completed
    total = len(backup_status["completed"]) + len(backup_status["errors"])
    backup_status["progress"] = min(10 + (total * 10), 95)

@app.route('/api/backup/trigger')
@requires_auth
@requires_permission('run_backup')
def trigger_backup():
    """Trigger backup via GET request."""
    global backup_status
    if backup_status["running"]:
        return jsonify({"error": "Backup ya en ejecución", "running": True})
    
    group = request.args.get('group')
    # Support multiple device parameters: ?device=A&device=B&device=C
    devices = request.args.getlist('device')
    
    # Capture user info for audit in background thread
    user_info = {
        'user_id': session.get('user_id'),
        'username': session.get('username', 'unknown'),
        'ip_address': request.remote_addr,
        'user_agent': parse_user_agent(request.headers.get('User-Agent', ''))
    }
    
    thread = threading.Thread(target=run_backup_async, args=(group, devices, user_info), daemon=True)
    thread.start()
    
    if devices:
        target = f"{len(devices)} equipo(s)"
        target_detail = devices
    else:
        target = group or "Todos"
        target_detail = group or "all"
    
    log_audit('backup_manual', entity_type='backup', entity_name=target, 
              details={'target': target_detail, 'group': group, 'devices': devices})
    
    return jsonify({"status": "started", "message": f"Backup iniciado: {target}", "running": True})

@app.route('/api/backup/status')
@requires_auth
def backup_status_api():
    return jsonify(backup_status)

@app.route('/api/backup/cancel')
@requires_auth
@requires_permission('run_backup')
def cancel_backup():
    """Cancel running backup."""
    global backup_status
    if backup_status["running"]:
        backup_status["cancelled"] = True
        backup_status["message"] = "Cancelando..."
        return jsonify({"status": "cancelling", "message": "Cancelando backup..."})
    return jsonify({"status": "not_running", "message": "No hay backup en ejecución"})

# ==========================
# API: INVENTORY CRUD
# ==========================

def load_inventory():
    """
    Load inventory from configured source (YAML or NetBox).
    Uses InventoryProvider for future NetBox integration.
    Returns dict with 'groups' key for backward compatibility.
    """
    try:
        from core.inventory_provider import get_inventory_provider
        provider = get_inventory_provider()
        return provider.get_raw_inventory()
    except Exception as e:
        log.warning(f"Error loading inventory via provider, falling back to YAML: {e}")
        # Fallback to direct YAML read
        try:
            with open(INVENTORY_FILE, 'r') as f:
                return yaml.safe_load(f) or {"groups": []}
        except Exception:
            return {"groups": []}

def save_inventory(data):
    with open(INVENTORY_FILE, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

def load_catalogs():
    """Load catalogs from database (localidades, tipos, modelos)."""
    db = get_db()
    return {
        'localidades': db.get_localidades(),
        'tipos': db.get_device_types(),
        'modelos': db.get_device_models()
    }

@app.route('/api/inventory')
@requires_auth
@requires_permission('view_inventory')
def api_get_inventory():
    return jsonify(load_inventory())

@app.route('/api/devices')
@requires_auth
@requires_permission('view_inventory')
def api_get_devices():
    """Get devices with server-side filtering and pagination."""
    inv = load_inventory()
    
    # Load localidades catalog to derive troncal from zona
    localidades_catalog = {}
    try:
        catalogs = load_catalogs()
        for loc in catalogs.get('localidades', []):
            localidades_catalog[loc.get('id', '').lower()] = loc.get('zona', '')
    except Exception:
        pass
    
    # Get filter params from URL
    f_localidad = request.args.get('localidad', '').lower()
    f_tipo = request.args.get('tipo', '').lower()
    f_vendor = request.args.get('vendor', '').lower()
    f_criticidad = request.args.get('criticidad', '').lower()
    f_grupo = request.args.get('grupo', '').lower()
    f_troncal = request.args.get('troncal', '').lower()
    f_tag = request.args.get('tag', '').lower()
    f_search = request.args.get('search', '').lower()
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    group_by = request.args.get('group_by', 'group')  # group, localidad, tipo, vendor, criticidad, troncal
    
    # Flatten all devices and apply filters
    all_devices = []
    for group in inv.get('groups', []):
        group_name = group.get('name', '')
        group_vendor = group.get('vendor', '')
        
        for device in group.get('devices', []):
            d_localidad = (device.get('localidad') or '').lower()
            d_tipo = (device.get('tipo') or '').lower()
            d_criticidad = (device.get('criticidad') or '').lower()
            # Derive troncal from localidad's zona
            d_troncal = localidades_catalog.get(d_localidad, '').lower()
            d_sysname = (device.get('sysname') or device.get('hostname') or '').lower()
            d_nombre = (device.get('nombre') or '').lower()
            d_ip = (device.get('ip') or '').lower()
            d_modelo = (device.get('modelo') or '').lower()
            d_tags = [t.lower() for t in device.get('tags', [])]
            
            # Apply filters
            if f_localidad and d_localidad != f_localidad:
                continue
            if f_tipo and d_tipo != f_tipo:
                continue
            if f_vendor and group_vendor.lower() != f_vendor:
                continue
            if f_criticidad and d_criticidad != f_criticidad:
                continue
            if f_grupo and group_name.lower() != f_grupo:
                continue
            if f_troncal and d_troncal != f_troncal:
                continue
            if f_tag and f_tag not in d_tags:
                continue
            
            # Global search - searches ALL fields
            if f_search:
                searchable = ' '.join([
                    d_sysname, d_nombre, d_ip, d_localidad, d_tipo,
                    d_modelo, d_troncal, group_vendor.lower(), group_name.lower(),
                    ' '.join(d_tags)
                ])
                if f_search not in searchable:
                    continue
            
            all_devices.append({
                'sysname': device.get('sysname') or device.get('hostname'),
                'hostname': device.get('hostname'),
                'nombre': device.get('nombre', ''),
                'ip': device.get('ip'),
                'localidad': device.get('localidad', ''),
                'tipo': device.get('tipo', ''),
                'modelo': device.get('modelo', ''),
                'criticidad': device.get('criticidad', ''),
                'troncal': localidades_catalog.get(d_localidad, ''),  # Derived from localidad's zona
                'tags': device.get('tags', []),
                'credential_ids': device.get('credential_ids', []),
                'group_name': group_name,
                'vendor': group_vendor
            })
    
    # Sort by sysname
    all_devices.sort(key=lambda x: x['sysname'].lower())
    
    # Get last backup status for all devices
    db = get_db()
    last_jobs = db.get_last_job_status_all()
    
    # Add backup_status to each device
    for d in all_devices:
        sysname = d.get('sysname') or d.get('hostname')
        job = last_jobs.get(sysname)
        if not job:
            d['backup_status'] = 'none'  # No backup yet
        elif job['status'] == 'ERROR':
            d['backup_status'] = 'error'  # Last backup failed
        elif job['changed']:
            d['backup_status'] = 'ok'  # Success with changes
        else:
            d['backup_status'] = 'unchanged'  # Success, no changes
    
    # Pagination
    total = len(all_devices)
    start = (page - 1) * per_page
    end = start + per_page
    paginated = all_devices[start:end]
    
    # Group the results if requested
    grouped = {}
    for d in paginated:
        if group_by == 'localidad':
            key = d['localidad'] or 'Sin definir'
        elif group_by == 'tipo':
            key = d['tipo'] or 'Sin definir'
        elif group_by == 'vendor':
            key = d['vendor'] or 'Sin definir'
        elif group_by == 'criticidad':
            key = d['criticidad'] or 'Sin definir'
        elif group_by == 'troncal':
            key = d['troncal'] or 'Sin definir'
        else:  # group
            key = d['group_name']
        
        if key not in grouped:
            grouped[key] = []
        grouped[key].append(d)
    
    return jsonify({
        'devices': paginated,
        'grouped': grouped,
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page if per_page > 0 else 1
    })

@app.route('/api/filter-options')
@requires_auth
@requires_permission('view_inventory')
def api_filter_options():
    """Get unique values for filter dropdowns."""
    inv = load_inventory()
    db = get_db()
    
    # Load catalogs for name lookups
    localidades_catalog = {}
    tipos_catalog = {}
    model_catalog = {}
    troncales = set()
    
    try:
        catalogs = load_catalogs()
        # Localidades: id -> name lookup, and also collect troncales (zonas)
        for loc in catalogs.get('localidades', []):
            loc_id = loc.get('id', '')
            localidades_catalog[loc_id] = loc.get('name', loc_id)
            if loc.get('zona'):
                troncales.add(loc['zona'])
        
        # Tipos: id -> name lookup
        for t in catalogs.get('tipos', []):
            tipos_catalog[t.get('id', '')] = t.get('name', t.get('id', ''))
        
        # Models: id -> name lookup
        for m in catalogs.get('modelos', []):
            model_catalog[m.get('id', '')] = m.get('name', m.get('id', ''))
    except Exception:
        pass
    
    localidades_ids = set()
    tipos_ids = set()
    vendors = set()
    grupos = set()
    tags = set()
    modelos_ids = set()
    
    for group in inv.get('groups', []):
        grupos.add(group.get('name', ''))
        vendors.add(group.get('vendor', ''))
        
        for device in group.get('devices', []):
            if device.get('localidad'):
                localidades_ids.add(device['localidad'])
            if device.get('tipo'):
                tipos_ids.add(device['tipo'])
            if device.get('modelo'):
                modelos_ids.add(device['modelo'])
            for tag in device.get('tags', []):
                tags.add(tag)
    
    # Build lists with id and display name
    localidades = []
    for loc_id in sorted(localidades_ids):
        localidades.append({
            'id': loc_id,
            'name': localidades_catalog.get(loc_id, loc_id.capitalize())
        })
    
    tipos = []
    for tipo_id in sorted(tipos_ids):
        tipos.append({
            'id': tipo_id,
            'name': tipos_catalog.get(tipo_id, tipo_id.upper())
        })
    
    modelos = []
    for model_id in sorted(modelos_ids):
        modelos.append({
            'id': model_id,
            'name': model_catalog.get(model_id, model_id)
        })
    
    return jsonify({
        'localidades': localidades,  # Now objects with id and name
        'tipos': tipos,  # Now objects with id and name
        'vendors': sorted(list(vendors)),
        'grupos': sorted(list(grupos)),
        'troncales': sorted(list(troncales)),
        'modelos': modelos,
        'tags': sorted(list(tags)),
        'criticidades': ['alta', 'media', 'baja']
    })

@app.route('/api/inventory/group', methods=['POST'])
@requires_auth
@requires_permission('edit_inventory')
def api_add_group():
    data = request.json
    inv = load_inventory()
    
    # Validate required fields
    name = data.get("name", "").strip()
    vendor = data.get("vendor", "").strip()
    credential_ids = data.get("credential_ids", [])
    
    if not name:
        return jsonify({"error": "Nombre es requerido"}), 400
    
    if not credential_ids:
        return jsonify({"error": "Seleccione al menos una credencial"}), 400
    
    # Check for duplicate
    for g in inv.get("groups", []):
        if g["name"] == name:
            return jsonify({"error": "Ya existe un grupo con ese nombre"}), 400
    
    new_group = {
        "name": name,
        "vendor": vendor,
        "credential_ids": credential_ids,
        "devices": []
    }
    if "groups" not in inv:
        inv["groups"] = []
    inv["groups"].append(new_group)
    save_inventory(inv)
    log_audit('group_create', entity_type='group', entity_id=name, entity_name=name, 
              details={'vendor': vendor})
    return jsonify({"status": "ok", "message": "Grupo creado"})

@app.route('/api/inventory/group/<group_name>', methods=['PUT'])
@requires_auth
@requires_permission('edit_inventory')
def api_edit_group(group_name):
    """Edit an existing group."""
    data = request.json
    inv = load_inventory()
    for g in inv.get("groups", []):
        if g["name"] == group_name:
            g["vendor"] = data.get("vendor", g.get("vendor", ""))
            if "credential_ids" in data:
                g["credential_ids"] = data["credential_ids"]
            save_inventory(inv)
            log_audit('group_update', entity_type='group', entity_id=group_name, entity_name=group_name, 
                      details={'vendor': data.get('vendor')})
            return jsonify({"status": "ok", "message": "Grupo actualizado"})
    return jsonify({"error": "Grupo no encontrado"}), 404

@app.route('/api/inventory/group/<group_name>', methods=['DELETE'])
@requires_auth
@requires_permission('edit_inventory')
def api_delete_group(group_name):
    """Delete a group (only if empty)."""
    inv = load_inventory()
    
    # Find the group and check if it has devices
    group = next((g for g in inv.get("groups", []) if g["name"] == group_name), None)
    if not group:
        return jsonify({"error": "Grupo no encontrado"}), 404
    
    device_count = len(group.get("devices", []))
    if device_count > 0:
        return jsonify({
            "error": f"No se puede eliminar el grupo '{group_name}' porque tiene {device_count} dispositivo(s). Muévelos a otro grupo primero."
        }), 400
    
    # Remove empty group
    inv["groups"] = [g for g in inv.get("groups", []) if g["name"] != group_name]
    
    save_inventory(inv)
    log_audit('group_delete', entity_type='group', entity_id=group_name, entity_name=group_name)
    return jsonify({"status": "ok", "message": "Grupo eliminado"})

@app.route('/api/vendors')
def api_get_vendors():
    """Return list of available vendor plugins."""
    import os
    vendors_dir = os.path.join(os.path.dirname(__file__), 'vendors')
    vendors = []
    for f in os.listdir(vendors_dir):
        if f.endswith('.py') and not f.startswith('_') and f != 'base_vendor.py':
            vendors.append(f.replace('.py', ''))
    return jsonify(vendors)

# ==========================
# API: CREDENTIAL VAULT
# ==========================

@app.route('/api/vault')
@requires_auth
@requires_permission('view_vault')
def api_get_vault():
    """Get all credentials (without passwords)."""
    from core.vault import get_credentials_list
    return jsonify(get_credentials_list())

@app.route('/api/vault', methods=['POST'])
@requires_auth
@requires_permission('edit_vault')
def api_add_vault_credential():
    """Add a new credential to vault."""
    from core.vault import add_credential
    data = request.json
    
    cred_id = data.get("id", "").strip().lower().replace(" ", "_")
    name = data.get("name", "").strip()
    user = data.get("user", "").strip()
    password = data.get("pass", "")
    extra_pass = data.get("extra_pass", "")
    
    if not cred_id or not name:
        return jsonify({"error": "ID y nombre son requeridos"}), 400
    
    success, message = add_credential(cred_id, name, user, password, extra_pass)
    
    if success:
        log_audit('credential_create', entity_type='credential', entity_id=cred_id, entity_name=name)
        return jsonify({"status": "ok", "message": message})
    return jsonify({"error": message}), 400

@app.route('/api/vault/<cred_id>', methods=['PUT'])
@requires_auth
@requires_permission('edit_vault')
def api_update_vault_credential(cred_id):
    """Update an existing credential."""
    from core.vault import update_credential
    data = request.json
    
    name = data.get("name")
    user = data.get("user")
    password = data.get("pass")
    extra_pass = data.get("extra_pass")
    
    success, message = update_credential(cred_id, name, user, password, extra_pass)
    
    if success:
        log_audit('credential_update', entity_type='credential', entity_id=cred_id, entity_name=name)
        return jsonify({"status": "ok", "message": message})
    return jsonify({"error": message}), 404

@app.route('/api/vault/<cred_id>', methods=['DELETE'])
@requires_auth
@requires_permission('edit_vault')
def api_delete_vault_credential(cred_id):
    """Delete a credential from vault."""
    from core.vault import delete_credential
    
    success, message = delete_credential(cred_id)
    
    if success:
        log_audit('credential_delete', entity_type='credential', entity_id=cred_id, entity_name=cred_id)
        return jsonify({"status": "ok", "message": message})
    return jsonify({"error": message}), 404

# ==========================
# ADMIN PAGE: VAULT
# ==========================

@app.route('/admin/vault')
@app.route('/inventory/vault')
@requires_auth
@requires_permission('view_vault')
def admin_vault():
    """Credential vault management page."""
    from core.vault import get_credentials_list
    credentials = get_credentials_list()
    return render_template('vault.html', credentials=credentials)

@app.route('/api/inventory/device', methods=['POST'])
@requires_auth
@requires_permission('edit_inventory')
def api_add_device():
    data = request.json
    inv = load_inventory()
    group_name = data.get("group")
    sysname = data.get("sysname") or data.get("hostname")
    
    if not sysname:
        return jsonify({"error": "Sysname es requerido"}), 400
    
    # Build device object with all fields
    device = {
        "sysname": sysname,
        "hostname": sysname,  # Compatibility
        "ip": data.get("ip")
    }
    
    # Add optional fields if provided
    if data.get("nombre"):
        device["nombre"] = data["nombre"]
    if data.get("localidad"):
        device["localidad"] = data["localidad"]
    if data.get("tipo"):
        device["tipo"] = data["tipo"]
    if data.get("modelo"):
        device["modelo"] = data["modelo"]
    if data.get("vendor"):
        device["vendor"] = data["vendor"]
    if data.get("criticidad"):
        device["criticidad"] = data["criticidad"]
    if data.get("tags"):
        device["tags"] = data["tags"]
    if data.get("credential_ids"):
        device["credential_ids"] = data["credential_ids"]
    
    for g in inv["groups"]:
        if g["name"] == group_name:
            # Check for duplicate sysname
            for d in g["devices"]:
                existing_sysname = d.get("sysname") or d.get("hostname")
                if existing_sysname == sysname:
                    return jsonify({"error": "Sysname ya existe en este grupo"}), 400
            g["devices"].append(device)
            save_inventory(inv)
            log_audit('device_create', entity_type='device', entity_id=sysname, 
                      entity_name=data.get('nombre', sysname), 
                      details={
                          'group': group_name, 
                          'ip': data.get('ip'),
                          'localidad': data.get('localidad'),
                          'tipo': data.get('tipo'),
                          'modelo': data.get('modelo'),
                          'vendor': data.get('vendor'),
                          'criticidad': data.get('criticidad')
                      })
            return jsonify({"status": "ok", "message": "Dispositivo agregado"})
    return jsonify({"error": "Grupo no encontrado"}), 404

@app.route('/api/inventory/device/<group_name>/<hostname>', methods=['DELETE'])
@requires_auth
@requires_permission('edit_inventory')
def api_delete_device(group_name, hostname):
    inv = load_inventory()
    for g in inv["groups"]:
        if g["name"] == group_name:
            g["devices"] = [d for d in g["devices"] if (d.get("sysname") or d.get("hostname")) != hostname]
            save_inventory(inv)
            log_audit('device_delete', entity_type='device', entity_id=hostname, entity_name=hostname, details={'group': group_name})
            return jsonify({"status": "ok", "message": "Dispositivo eliminado"})
    return jsonify({"error": "No encontrado"}), 404

@app.route('/api/inventory/device/<group_name>/<hostname>', methods=['PUT'])
@requires_auth
@requires_permission('edit_inventory')
def api_edit_device(group_name, hostname):
    """Edit an existing device. Supports moving to different group. Sysname is immutable."""
    data = request.json
    inv = load_inventory()
    
    new_group = data.get("group", group_name)
    new_ip = data.get("ip")
    
    # Find and remove device from original group
    device_data = None
    for g in inv["groups"]:
        if g["name"] == group_name:
            for i, d in enumerate(g["devices"]):
                existing_sysname = d.get("sysname") or d.get("hostname")
                if existing_sysname == hostname:
                    device_data = g["devices"].pop(i)
                    break
            break
    
    if not device_data:
        return jsonify({"error": "Dispositivo no encontrado"}), 404
    
    # Capture original values for audit
    original_values = {
        'group': group_name,
        'ip': device_data.get('ip'),
        'nombre': device_data.get('nombre'),
        'localidad': device_data.get('localidad'),
        'tipo': device_data.get('tipo'),
        'modelo': device_data.get('modelo'),
        'vendor': device_data.get('vendor'),
        'criticidad': device_data.get('criticidad'),
    }
    
    # Keep sysname immutable
    original_sysname = device_data.get("sysname") or device_data.get("hostname")
    device_data["sysname"] = original_sysname
    device_data["hostname"] = original_sysname  # Compatibility
    
    # Update mutable fields
    if new_ip:
        device_data["ip"] = new_ip
    
    # Update optional fields
    for field in ["nombre", "localidad", "tipo", "modelo", "vendor", "criticidad"]:
        if field in data:
            if data[field]:
                device_data[field] = data[field]
            elif field in device_data:
                del device_data[field]
    
    # Handle tags
    if "tags" in data:
        if data["tags"]:
            device_data["tags"] = data["tags"]
        elif "tags" in device_data:
            del device_data["tags"]
    
    # Handle credential_ids
    if "credential_ids" in data:
        if data["credential_ids"]:
            device_data["credential_ids"] = data["credential_ids"]
        elif "credential_ids" in device_data:
            del device_data["credential_ids"]
    
    # Track changes for audit
    changes = {}
    new_values = {
        'group': new_group,
        'ip': device_data.get('ip'),
        'nombre': device_data.get('nombre'),
        'localidad': device_data.get('localidad'),
        'tipo': device_data.get('tipo'),
        'modelo': device_data.get('modelo'),
        'vendor': device_data.get('vendor'),
        'criticidad': device_data.get('criticidad'),
    }
    for key, old_val in original_values.items():
        new_val = new_values.get(key)
        if old_val != new_val:
            changes[key] = f"{old_val or '-'} → {new_val or '-'}"
    
    # Add to target group (same or different)
    for g in inv["groups"]:
        if g["name"] == new_group:
            g["devices"].append(device_data)
            save_inventory(inv)
            log_audit('device_update', entity_type='device', entity_id=original_sysname, 
                      entity_name=device_data.get('nombre', original_sysname), 
                      details={'changes': changes, 'group': new_group})
            return jsonify({"status": "ok", "message": "Dispositivo actualizado"})
    
    # If target group not found, put back in original
    for g in inv["groups"]:
        if g["name"] == group_name:
            g["devices"].append(device_data)
    save_inventory(inv)
    return jsonify({"error": "Grupo destino no encontrado"}), 404

@app.route('/api/inventory/device/<group_name>/<hostname>/toggle-enabled', methods=['PUT'])
@requires_auth
@requires_permission('edit_inventory')
def api_toggle_device_enabled(group_name, hostname):
    """
    Enable or disable a device for backup.
    Reason is REQUIRED when disabling.
    """
    data = request.json
    enabled = data.get('enabled', True)
    reason = data.get('reason', '').strip()
    
    # Reason is required when disabling
    if not enabled and not reason:
        return jsonify({"error": "El motivo es requerido al deshabilitar un dispositivo"}), 400
    
    inv = load_inventory()
    
    for g in inv["groups"]:
        if g["name"] == group_name:
            for d in g["devices"]:
                existing_sysname = d.get("sysname") or d.get("hostname")
                if existing_sysname == hostname:
                    # Update enabled status
                    d["enabled"] = enabled
                    
                    if enabled:
                        # Clear disable metadata when enabling
                        d.pop("disabled_by", None)
                        d.pop("disabled_at", None)
                        d.pop("disabled_reason", None)
                        event_type = 'device_enable'
                        details = {}
                    else:
                        # Record who disabled and why
                        d["disabled_by"] = session.get('username', 'unknown')
                        d["disabled_at"] = datetime.now().isoformat()
                        d["disabled_reason"] = reason
                        event_type = 'device_disable'
                        details = {'reason': reason}
                    
                    save_inventory(inv)
                    log_audit(event_type, entity_type='device', entity_id=hostname, 
                              entity_name=d.get('nombre', hostname), details=details)
                    
                    status_text = "habilitado" if enabled else "deshabilitado"
                    return jsonify({"status": "ok", "message": f"Dispositivo {status_text}"})
            
            return jsonify({"error": "Dispositivo no encontrado"}), 404
    
    return jsonify({"error": "Grupo no encontrado"}), 404

@app.route('/api/inventory/test', methods=['POST'])
@requires_auth
@requires_permission('view_inventory')
def api_test_connection():
    """Test connection to a device before saving."""
    import socket
    data = request.json
    ip = data.get("ip")
    port = data.get("port", 23)
    
    if not ip:
        return jsonify({"success": False, "error": "IP requerida"})
    
    # Validate IP format
    try:
        socket.inet_aton(ip)
    except socket.error:
        return jsonify({"success": False, "error": "Formato de IP inválido"})
    
    # Test TCP connection
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        if result == 0:
            return jsonify({"success": True, "message": f"Conexión OK a {ip}:{port}"})
        else:
            return jsonify({"success": False, "error": f"Puerto {port} cerrado o inaccesible"})
    except socket.timeout:
        return jsonify({"success": False, "error": "Timeout conectando"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# ==========================
# API: FILE BROWSER
# ==========================

@app.route('/api/files/list')
@app.route('/api/files/list/<path:subpath>')
def api_list_files(subpath=""):
    view = request.args.get('view', 'physical')
    base = ARCHIVE_DIR
    
    # Build device name lookup from inventory
    inv = load_inventory()
    device_names = {}
    for g in inv.get('groups', []):
        for d in g.get('devices', []):
            sysname = d.get('sysname', d.get('hostname', ''))
            nombre = d.get('nombre', d.get('name', sysname))
            device_names[sysname] = nombre
    
    # Helper to safe list directory
    def list_dir_safe(path, relative_to):
        target = os.path.abspath(os.path.join(base, path))
        if not target.startswith(os.path.abspath(base)):
            return jsonify({"error": "Access denied"}), 403
        if not os.path.exists(target):
            return jsonify({"error": "Path not found"}), 404
        items = []
        for entry in os.scandir(target):
            item = {
                "name": entry.name,
                "is_dir": entry.is_dir(),
                "size": entry.stat().st_size if entry.is_file() else 0,
                "mtime": datetime.fromtimestamp(entry.stat().st_mtime).isoformat()
            }
            # Add display_name if this directory matches a device
            if entry.is_dir() and entry.name in device_names:
                item["display_name"] = device_names[entry.name]
            items.append(item)
        return jsonify({"path": relative_to, "items": sorted(items, key=lambda x: (not x["is_dir"], x["name"]))})

    if view in ('physical', 'direct'):
        # Direct physical browsing (vendor/device/files or device files directly)
        return list_dir_safe(subpath, subpath)

    # Virtual Views Logic
    parts = subpath.split('/') if subpath else []
    
    # helper to get categories from inventory with display names
    def get_categories(key):
        # Vendor friendly names
        vendor_names = {
            'hp': 'HP', 'huawei': 'Huawei', 'zte_olt': 'OLT ZTE', 'zteolt': 'OLT ZTE',
            'cisco': 'Cisco', 'mikrotik': 'MikroTik', 'juniper': 'Juniper', 'fortinet': 'Fortinet'
        }
        inv = load_inventory()
        cats = set()
        for g in inv.get('groups', []):
            if key == 'vendor':
                # Include group vendor if defined
                grp_vendor = g.get('vendor', '')
                if grp_vendor:
                    cats.add(grp_vendor)
                # Also include device-level vendors (for mixed groups)
                for d in g.get('devices', []):
                    dev_vendor = d.get('vendor', '')
                    if dev_vendor:
                        cats.add(dev_vendor)
            else:
                for d in g.get('devices', []):
                    val = d.get(key)
                    if val: cats.add(val)
        # Convert to list of dicts with display names
        result = []
        for c in sorted(list(cats)):
            if key == 'vendor':
                display = vendor_names.get(c.lower(), c.capitalize())
            else:
                display = c.capitalize() if c else c
            result.append({'name': c, 'display_name': display})
        return result
        
    # helper to get devices in category with display names
    def get_devices(cat_key, cat_val):
        inv = load_inventory()
        devices = []
        for g in inv.get('groups', []):
            g_vendor = g.get('vendor', '').lower()
            for d in g.get('devices', []):
                match = False
                if cat_key == 'vendor':
                    # Check device vendor first (for mixed groups), then group vendor
                    dev_vendor = (d.get('vendor') or '').lower()
                    grp_vendor = g_vendor
                    match = dev_vendor == cat_val.lower() or (not dev_vendor and grp_vendor == cat_val.lower())
                else: match = (d.get(cat_key) or '').lower() == cat_val.lower()
                
                if match:
                    sysname = d.get('sysname') or d.get('hostname')
                    nombre = d.get('nombre', d.get('name', sysname))
                    devices.append({'name': sysname, 'display_name': nombre})
        # Remove duplicates and sort
        seen = set()
        unique = []
        for dev in devices:
            if dev['name'] not in seen:
                seen.add(dev['name'])
                unique.append(dev)
        return sorted(unique, key=lambda x: x['display_name'])

    # ROOT: List categories (virtual folders)
    if not parts:
        cats = []
        if view == 'localidad': cats = get_categories('localidad')
        elif view == 'tipo': cats = get_categories('tipo')
        elif view == 'vendor': cats = get_categories('vendor')
        elif view in ('grupo', 'physical'):
            # List custom groups from inventory
            inv = load_inventory()
            for g in inv.get('groups', []):
                g_name = g.get('name', g.get('vendor', 'Unknown'))
                cats.append({'name': g_name, 'display_name': g_name})
            cats = sorted(cats, key=lambda x: x['display_name'])
        
        return jsonify({
            "path": "",
            "items": [{"name": c['name'], "display_name": c['display_name'], "is_dir": True, "size": 0, "mtime": datetime.now().isoformat()} for c in cats]
        })

    # LEVEL 1: Category selected -> List devices (virtual folders)
    category = parts[0]
    if len(parts) == 1:
        if view in ('grupo', 'physical'):
            # List devices in the selected group
            inv = load_inventory()
            devices = []
            for g in inv.get('groups', []):
                g_name = g.get('name', g.get('vendor', ''))
                if g_name.lower() == category.lower():
                    for d in g.get('devices', []):
                        sysname = d.get('sysname') or d.get('hostname')
                        nombre = d.get('nombre', d.get('name', sysname))
                        devices.append({'name': sysname, 'display_name': nombre})
            devices = sorted(devices, key=lambda x: x['display_name'])
            return jsonify({
                "path": category,
                "items": [{"name": d['name'], "display_name": d['display_name'], "is_dir": True, "size": 0, "mtime": datetime.now().isoformat()} for d in devices]
            })
        else:
            devices = get_devices(view, category)
            return jsonify({
                "path": category,
                "items": [{"name": d['name'], "display_name": d['display_name'], "is_dir": True, "size": 0, "mtime": datetime.now().isoformat()} for d in devices]
            })

    # LEVEL 2+: Device selected -> List actual files from physical path
    device_name = parts[1]
    
    # Find physical path for device
    inv = load_inventory()
    phys_path = None
    for g in inv.get('groups', []):
        for d in g.get('devices', []):
            if (d.get('sysname') or d.get('hostname')).lower() == device_name.lower():
                # Physical folder structure: /archive/{vendor}/{sysname}/
                # Use device vendor first (for mixed groups), fallback to group vendor
                device_vendor = d.get('vendor', '')
                group_vendor = g.get('vendor', '')
                vendor_name = normalize_vendor_folder(device_vendor or group_vendor)
                device_folder_name = d.get('sysname') or d.get('hostname')
                phys_path = os.path.join(vendor_name, device_folder_name)
                break
        if phys_path: break
    
    if not phys_path:
        return jsonify({"error": "Device path not found"}), 404
        
    # Subpath inside the device folder
    remaining_path = os.path.join(*parts[2:]) if len(parts) > 2 else ""
    full_phys_path = os.path.join(phys_path, remaining_path)
    
    return list_dir_safe(full_phys_path, subpath)

@app.route('/api/files/content/<path:filepath>')
def api_file_content(filepath):
    base = ARCHIVE_DIR
    
    # Helper function to resolve virtual path to physical path
    def resolve_virtual_path(vpath):
        """
        Resolve virtual browser path to physical archive path.
        Virtual: grupo/Huawei/DEVICE/file.cfg or localidad/cello/DEVICE/file.cfg
        Physical: vendor/DEVICE/file.cfg (e.g., huawei/DEVICE/file.cfg)
        """
        parts = vpath.split('/')
        if len(parts) < 2:
            return vpath  # Already physical or too short
        
        # Find the device in the path and lookup its physical location
        inv = load_inventory()
        
        # Try to find a device match anywhere in the path
        for i, part in enumerate(parts):
            for g in inv.get('groups', []):
                for d in g.get('devices', []):
                    sysname = d.get('sysname') or d.get('hostname')
                    if sysname and sysname.lower() == part.lower():
                        # Found device! Build physical path
                        # Use device vendor first (for mixed groups), fallback to group vendor
                        device_vendor = d.get('vendor', '')
                        group_vendor = g.get('vendor', '')
                        vendor = normalize_vendor_folder(device_vendor or group_vendor)
                        remaining = '/'.join(parts[i+1:]) if i+1 < len(parts) else ''
                        if remaining:
                            return os.path.join(vendor, sysname, remaining)
                        else:
                            return os.path.join(vendor, sysname)
        
        # Fallback: return as-is (might already be physical)
        return vpath
    
    # Resolve virtual path to physical
    physical_path = resolve_virtual_path(filepath)
    
    target = os.path.abspath(os.path.join(base, physical_path))
    if not target.startswith(os.path.abspath(base)):
        return jsonify({"error": "Access denied"}), 403
    
    if not os.path.isfile(target):
        # Log for debugging
        log.debug(f"File not found: {target} (original path: {filepath})")
        return jsonify({"error": "File not found"}), 404
    
    try:
        with open(target, 'r', errors='ignore') as f:
            content = f.read()
        return jsonify({"filename": os.path.basename(filepath), "content": content})
    except Exception:
        return jsonify({"error": "Cannot read file"}), 500


@app.route('/api/files/delete/<path:filepath>', methods=['DELETE'])
@requires_auth
def api_delete_file(filepath):
    """Delete a file from the archive directory."""
    target = os.path.join(ARCHIVE_DIR, filepath)
    
    # Security: ensure path is within ARCHIVE_DIR
    if not os.path.realpath(target).startswith(os.path.realpath(ARCHIVE_DIR)):
        return jsonify({"success": False, "error": "Acceso denegado"}), 403
    
    if not os.path.exists(target):
        return jsonify({"success": False, "error": "Archivo no encontrado"}), 404
    
    try:
        if os.path.isdir(target):
            import shutil
            shutil.rmtree(target)
            return jsonify({"success": True, "message": f"Carpeta '{filepath}' eliminada"})
        else:
            os.remove(target)
            return jsonify({"success": True, "message": f"Archivo '{filepath}' eliminado"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ==========================
# API: DIFF VIEWER
# ==========================

@app.route('/api/diff/<vendor>/<hostname>')
def api_get_diff(vendor, hostname):
    """Get git diff history for a device config."""
    # Check if repo exists
    if not os.path.exists(REPO_DIR):
        return jsonify({
            "error": f"Repositorio no encontrado: {REPO_DIR}. Ejecute un backup primero.",
            "diff": ""
        })
    
    # Check if it's a git repo
    if not os.path.exists(os.path.join(REPO_DIR, '.git')):
        return jsonify({
            "error": "El directorio no es un repositorio Git. Inicialice con: cd /Backup/repo && git init",
            "diff": ""
        })
    
    # Normalize vendor name: try both zte_olt and zteolt (class name is lowercase without underscores)
    vendor_variants = [vendor, vendor.replace('_', '')]
    
    repo_file = None
    for v in vendor_variants:
        for ext in ['.cfg', '.txt', '.dat', '']:
            candidate = os.path.join(REPO_DIR, v, f"{hostname}{ext}")
            if os.path.exists(candidate):
                repo_file = candidate
                break
        if repo_file:
            break
    
    if not repo_file:
        return jsonify({
            "error": f"No se encontró configuración para {hostname} en el repositorio. Ejecute un backup primero.",
            "diff": ""
        })
    
    try:
        # Use full path to git to avoid PATH issues with systemd
        git_path = "/usr/bin/git"
        
        # Check if git is available
        result = subprocess.run(
            [git_path, "--version"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            return jsonify({"error": "Git no está instalado en el servidor", "diff": ""})
        
        # Get log with diffs
        rel_path = os.path.relpath(repo_file, REPO_DIR)
        result = subprocess.run(
            [git_path, "log", "-p", "-5", "--pretty=format:=== Commit: %h (%ai) ===\n%s\n", "--", rel_path],
            cwd=REPO_DIR, capture_output=True, text=True,
            encoding='utf-8', errors='replace'  # Handle files with invalid encoding
        )
        
        if result.returncode != 0:
            return jsonify({"error": f"Error git: {result.stderr}", "diff": ""})
        
        if not result.stdout.strip():
            return jsonify({
                "hostname": hostname,
                "diff": "Sin historial de cambios registrados.\nEl archivo existe pero aún no ha sido versionado con git."
            })
        
        return jsonify({"hostname": hostname, "diff": result.stdout})
        
    except FileNotFoundError:
        return jsonify({"error": "Git no está instalado. Instale con: apt install git", "diff": ""})
    except Exception as e:
        return jsonify({"error": str(e), "diff": ""})

# ==========================
# API: STATS 24H (for dynamic refresh)
# ==========================

@app.route('/api/stats/24h')
def api_stats_24h():
    """Get 24h stats for dynamic dashboard refresh."""
    db = get_db()
    stats = db.get_stats_24h()
    try:
        total, used, free = shutil.disk_usage(BACKUP_ROOT_DIR)
        disk_info = {
            "percent": round((used / total) * 100, 1),
            "free_gb": round(free / (1024**3), 2),
            "total_gb": round(total / (1024**3), 2)
        }
    except Exception:
        disk_info = {"percent": 0, "free_gb": 0, "total_gb": 0}
    return jsonify({"stats": stats, "disk": disk_info})

# ==========================
# API: STATS HISTORY
# ==========================

@app.route('/api/stats/history')
def api_stats_history():
    db = get_db()
    conn = db._get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT date(timestamp) as day, status, count(*) 
        FROM jobs 
        WHERE timestamp >= date('now', '-7 days')
        GROUP BY date(timestamp), status
        ORDER BY day
    ''')
    rows = cursor.fetchall()
    conn.close()
    
    data = {}
    for day, status, count in rows:
        if day not in data:
            data[day] = {"SUCCESS": 0, "ERROR": 0}
        data[day][status] = count
    
    return jsonify(data)

@app.route('/api/stats/by_group')
def api_stats_by_group():
    """Get stats per group for the last 24 hours."""
    db = get_db()
    conn = db._get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT group_name, status, count(*) 
        FROM jobs 
        WHERE timestamp >= datetime('now', '-24 hours')
        GROUP BY group_name, status
    ''')
    rows = cursor.fetchall()
    conn.close()
    
    # Format: {group_name: {SUCCESS: X, ERROR: Y}}
    data = {}
    for group, status, count in rows:
        if group not in data:
            data[group] = {"SUCCESS": 0, "ERROR": 0, "total": 0}
        data[group][status] = count
        data[group]["total"] += count
    
    return jsonify(data)

@app.route('/api/jobs')
def api_jobs_paginated():
    """Get paginated jobs list with filters."""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    
    # Filters
    filters = {}
    
    # 1. Filter by status/vendor directly
    status = request.args.get('status')
    if status:
        filters['status'] = status
        
    vendor = request.args.get('vendor')
    if vendor:
        filters['vendor'] = vendor.lower()
    
    # 2. Search filter
    search = request.args.get('search')
    if search:
        filters['search'] = search.lower()
    
    # 3. Filter by localidad/troncal/tipo/grupo/criticidad/modelo requires inventory lookup
    localidad = request.args.get('localidad')
    troncal = request.args.get('troncal')
    tipo = request.args.get('tipo')
    grupo = request.args.get('grupo')
    criticidad = request.args.get('criticidad')
    modelo = request.args.get('modelo')
    
    # If any inventory-based filter, load inventory and catalogs
    if localidad or troncal or tipo or grupo or criticidad or modelo:
        inv = load_inventory()
        catalogs = load_catalogs()
        
        # Build lookup: localidad -> zona (troncal)
        loc_zona_map = {}
        for loc in catalogs.get('localidades', []):
            loc_zona_map[loc.get('id', '').lower()] = (loc.get('zona') or '').lower()
        
        matching_hosts = []
        for group in inv.get('groups', []):
            g_name = group.get('name', '')
            g_vendor = group.get('vendor', '').lower()
            
            for device in group.get('devices', []):
                d_loc = (device.get('localidad') or '').lower()
                d_tipo = (device.get('tipo') or '').lower()
                d_crit = (device.get('criticidad') or '').lower()
                d_modelo = (device.get('modelo') or '').lower()
                d_troncal = loc_zona_map.get(d_loc, '')
                
                match = True
                if localidad and d_loc != localidad.lower():
                    match = False
                if troncal and d_troncal != troncal.lower():
                    match = False
                if tipo and d_tipo != tipo.lower():
                    match = False
                if grupo and g_name.lower() != grupo.lower():
                    match = False
                if criticidad and d_crit != criticidad.lower():
                    match = False
                if modelo and d_modelo != modelo.lower():
                    match = False
                    
                if match:
                    matching_hosts.append(device.get('sysname') or device.get('hostname'))
        
        filters['hostname_in'] = matching_hosts

    db = get_db()
    
    # Get total and jobs
    total = db.get_jobs_count(filters)
    raw_jobs = db.get_jobs(page, per_page, filters)
    
    # Build device name lookup from inventory for friendly display
    inv = load_inventory()
    device_names = {}
    for group in inv.get('groups', []):
        for device in group.get('devices', []):
            sysname = device.get('sysname') or device.get('hostname')
            if sysname:
                device_names[sysname] = device.get('nombre') or sysname
    
    # Vendor friendly names
    vendor_names = {
        'hp': 'HP', 'huawei': 'Huawei', 'zte_olt': 'OLT ZTE',
        'cisco': 'Cisco', 'mikrotik': 'MikroTik', 'juniper': 'Juniper', 'fortinet': 'Fortinet'
    }
    
    # Format for API
    jobs = []
    for row in raw_jobs:
        hostname = row['hostname']
        vendor_id = row['vendor'] or ''
        vendor_display = vendor_names.get(vendor_id.lower(), vendor_id.capitalize() if vendor_id else '')
        
        jobs.append({
            "id": row['id'], 
            "hostname": hostname,
            "nombre": device_names.get(hostname, hostname),  # Friendly name
            "vendor": vendor_id,
            "vendor_name": vendor_display,  # Friendly vendor name
            "group_name": row['group_name'],
            "status": row['status'], 
            "message": row['message'], 
            "timestamp": row['timestamp'], 
            "duration": row['duration_seconds'], 
            "changed": row['changed']
        })
    
    return jsonify({
        "jobs": jobs,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page
    })

# ==========================
# PAGES
# ==========================

@app.route('/inventory', methods=['GET', 'POST'])
@requires_auth
@requires_permission('view_inventory')
def inventory():
    if request.method == 'POST':
        try:
            new_data = yaml.safe_load(request.form.get('yaml_content'))
            if not new_data:
                raise ValueError("Empty YAML")
            save_inventory(new_data)
            return redirect(url_for('inventory'))
        except Exception as e:
            return f"Error: {e}", 400
    
    try:
        with open(INVENTORY_FILE, 'r') as f:
            content = f.read()
    except Exception:
        content = "# Inventory not found"
    
    inv = load_inventory()
    return render_template('inventory.html', content=content, inventory=inv)

@app.route('/files')
@app.route('/files/<path:subpath>')
@app.route('/backups')
@app.route('/backups/<path:subpath>')
@requires_auth
def files_browser(subpath=""):
    return render_template('files.html', current_path=subpath)

@app.route('/diff/<vendor>/<hostname>')
@requires_auth
def diff_page(vendor, hostname):
    return render_template('diff.html', vendor=vendor, hostname=hostname)

@app.route('/download/<path:filepath>')
@requires_auth
def download_file(filepath):
    safe_path = os.path.abspath(os.path.join(ARCHIVE_DIR, filepath))
    if not safe_path.startswith(os.path.abspath(ARCHIVE_DIR)):
        return abort(403)
    if not os.path.exists(safe_path):
        return abort(404)
    
    # Audit log for file download
    filename = os.path.basename(safe_path)
    log_audit('file_download', entity_type='file', entity_id=filepath, entity_name=filename)
    
    return send_from_directory(os.path.dirname(safe_path), os.path.basename(safe_path), as_attachment=True)

@app.route('/api/files/zip-info/<path:folderpath>')
@requires_auth
@requires_permission('view_files')
def api_zip_info(folderpath):
    """
    Get information about a folder for ZIP download confirmation.
    Returns list of subdirectories, file counts, and sizes.
    """
    inv = load_inventory()
    view = request.args.get('view', 'grupo')
    parts = folderpath.split('/')
    
    # Resolve virtual path to physical paths (may return multiple for groups)
    physical_paths = resolve_zip_paths(folderpath, view, inv)
    
    if not physical_paths:
        return jsonify({'error': 'Path not found', 'folders': []}), 404
    
    folders_info = []
    total_files = 0
    total_size = 0
    
    for ppath in physical_paths:
        safe_path = os.path.abspath(os.path.join(ARCHIVE_DIR, ppath))
        if not safe_path.startswith(os.path.abspath(ARCHIVE_DIR)):
            continue
        if not os.path.exists(safe_path):
            continue
            
        folder_name = os.path.basename(ppath)
        file_count = 0
        folder_size = 0
        
        for root, dirs, files in os.walk(safe_path):
            for f in files:
                file_count += 1
                try:
                    folder_size += os.path.getsize(os.path.join(root, f))
                except:
                    pass
        
        folders_info.append({
            'name': folder_name,
            'path': ppath,
            'files': file_count,
            'size': folder_size,
            'size_human': format_size(folder_size)
        })
        total_files += file_count
        total_size += folder_size
    
    return jsonify({
        'folders': folders_info,
        'total_files': total_files,
        'total_size': total_size,
        'total_size_human': format_size(total_size)
    })

def format_size(size_bytes):
    """Format bytes as human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"

def resolve_zip_paths(folderpath, view, inv):
    """
    Resolve virtual path to physical path(s).
    For groups/localidades, returns list of all device folders.
    For device folders, returns single path.
    """
    parts = folderpath.split('/')
    physical_paths = []
    
    # Direct path - check if it exists
    direct_path = os.path.join(ARCHIVE_DIR, folderpath)
    if os.path.exists(direct_path) and os.path.isdir(direct_path):
        return [folderpath]
    
    # Virtual path resolution based on view type
    if view == 'grupo':
        # First part might be a group name
        group_name = parts[0]
        for group in inv.get('groups', []):
            if group.get('name', '').lower() == group_name.lower():
                group_vendor = group.get('vendor', '')
                if len(parts) == 1:
                    # Group level - return all device folders
                    for device in group.get('devices', []):
                        sysname = device.get('sysname') or device.get('hostname')
                        if sysname:
                            # Use device vendor first, fallback to group vendor
                            device_vendor = device.get('vendor', '')
                            vendor_folder = normalize_vendor_folder(device_vendor or group_vendor)
                            device_path = os.path.join(vendor_folder, sysname)
                            if os.path.exists(os.path.join(ARCHIVE_DIR, device_path)):
                                physical_paths.append(device_path)
                else:
                    # Device level inside group - find the specific device
                    device_name = parts[1]
                    for device in group.get('devices', []):
                        sysname = device.get('sysname') or device.get('hostname')
                        if sysname and sysname.lower() == device_name.lower():
                            device_vendor = device.get('vendor', '')
                            vendor_folder = normalize_vendor_folder(device_vendor or group_vendor)
                            device_path = os.path.join(vendor_folder, sysname)
                            if os.path.exists(os.path.join(ARCHIVE_DIR, device_path)):
                                physical_paths.append(device_path)
                            break
                break
    
    elif view == 'vendor':
        # First part is vendor folder - normalize it
        vendor_folder = normalize_vendor_folder(parts[0])
        if len(parts) >= 2:
            device_path = os.path.join(vendor_folder, parts[1])
            if os.path.exists(os.path.join(ARCHIVE_DIR, device_path)):
                physical_paths.append(device_path)
        else:
            # All devices of this vendor
            vendor_path = os.path.join(ARCHIVE_DIR, vendor_folder)
            if os.path.exists(vendor_path):
                for item in os.listdir(vendor_path):
                    item_path = os.path.join(vendor_folder, item)
                    if os.path.isdir(os.path.join(ARCHIVE_DIR, item_path)):
                        physical_paths.append(item_path)
    
    elif view == 'localidad':
        localidad_name = parts[0]
        for group in inv.get('groups', []):
            group_vendor = group.get('vendor', '')
            for device in group.get('devices', []):
                device_loc = device.get('localidad', '')
                if device_loc.lower() == localidad_name.lower():
                    sysname = device.get('sysname') or device.get('hostname')
                    if sysname:
                        if len(parts) == 1 or (len(parts) >= 2 and parts[1].lower() == sysname.lower()):
                            # Use device vendor first, fallback to group vendor
                            device_vendor = device.get('vendor', '')
                            vendor_folder = normalize_vendor_folder(device_vendor or group_vendor)
                            device_path = os.path.join(vendor_folder, sysname)
                            if os.path.exists(os.path.join(ARCHIVE_DIR, device_path)):
                                physical_paths.append(device_path)
    
    elif view == 'tipo':
        tipo_name = parts[0]
        for group in inv.get('groups', []):
            group_vendor = group.get('vendor', '')
            for device in group.get('devices', []):
                device_tipo = device.get('tipo', '')
                if device_tipo.lower() == tipo_name.lower():
                    sysname = device.get('sysname') or device.get('hostname')
                    if sysname:
                        if len(parts) == 1 or (len(parts) >= 2 and parts[1].lower() == sysname.lower()):
                            # Use device vendor first, fallback to group vendor
                            device_vendor = device.get('vendor', '')
                            vendor_folder = normalize_vendor_folder(device_vendor or group_vendor)
                            device_path = os.path.join(vendor_folder, sysname)
                            if os.path.exists(os.path.join(ARCHIVE_DIR, device_path)):
                                physical_paths.append(device_path)
    
    return physical_paths

@app.route('/download-zip/<path:folderpath>')
@requires_auth
@requires_permission('view_files')
def download_zip(folderpath):
    """
    Download a folder (or multiple folders for groups) as a ZIP file.
    """
    import zipfile
    from io import BytesIO
    
    inv = load_inventory()
    view = request.args.get('view', 'grupo')
    
    physical_paths = resolve_zip_paths(folderpath, view, inv)
    
    if not physical_paths:
        return jsonify({'error': 'Path not found'}), 404
    
    # Generate ZIP in memory
    memory_file = BytesIO()
    
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for ppath in physical_paths:
            safe_path = os.path.abspath(os.path.join(ARCHIVE_DIR, ppath))
            if not safe_path.startswith(os.path.abspath(ARCHIVE_DIR)):
                continue
            if not os.path.exists(safe_path):
                continue
                
            folder_name = os.path.basename(ppath)
            
            if os.path.isdir(safe_path):
                for root, dirs, files in os.walk(safe_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        # Archive name includes folder name to group files
                        arcname = os.path.join(folder_name, os.path.relpath(file_path, safe_path))
                        zf.write(file_path, arcname)
            else:
                # Single file
                zf.write(safe_path, folder_name)
    
    memory_file.seek(0)
    
    # Generate filename from path
    zip_filename = folderpath.replace('/', '_').replace('\\', '_') + '.zip'
    
    return Response(
        memory_file.getvalue(),
        mimetype='application/zip',
        headers={
            'Content-Disposition': f'attachment; filename="{zip_filename}"',
            'Content-Type': 'application/zip'
        }
    )


# ==========================
# ADMIN: SETTINGS
# ==========================

@app.route('/admin/settings')
@requires_auth
@requires_permission('view_settings')
def admin_settings():
    cfg = get_config_manager()
    settings = cfg.get_all_settings()
    
    # Check if user can send test emails (use get_current_user() to get fresh data from DB)
    user = get_current_user()
    can_test_email = has_permission(user, 'test_email') if user else False
    can_edit_settings = has_permission(user, 'edit_settings') if user else False
    
    # Get unique vendors from inventory (dynamic, not hardcoded)
    inv = load_inventory()
    vendors_set = set()
    for group in inv.get('groups', []):
        vendor = group.get('vendor', '')
        if vendor:
            vendors_set.add(vendor)
    vendors = sorted(list(vendors_set))
    
    return render_template('settings.html', 
                          settings=settings, 
                          can_test_email=can_test_email,
                          can_edit_settings=can_edit_settings,
                          vendors=vendors)

@app.route('/api/settings', methods=['GET'])
@requires_auth
@requires_permission('view_settings')
def api_get_settings():
    cfg = get_config_manager()
    return jsonify(cfg.get_all_settings())

@app.route('/api/settings', methods=['PUT'])
@requires_auth
@requires_permission('edit_settings')
def api_update_settings():
    cfg = get_config_manager()
    data = request.json
    
    # Get user for audit before any changes
    current_user = get_current_user()
    username = current_user.get('username', 'unknown') if current_user else 'unknown'
    changed_keys = list(data.keys())
    
    # Validate schedule formats (HH:MM,HH:MM,...)
    def validate_schedule_format(value):
        """Validate schedule string is valid HH:MM format."""
        if not value or not value.strip():
            return True  # Empty is valid (inherit from parent)
        import re
        for time_str in value.split(','):
            time_str = time_str.strip()
            if not time_str:
                continue
            if not re.match(r'^\d{2}:\d{2}$', time_str):
                return False
            h, m = time_str.split(':')
            if not (0 <= int(h) <= 23 and 0 <= int(m) <= 59):
                return False
        return True
    
    # Check all schedule-related keys
    schedule_keys = [k for k in data.keys() if 'schedule' in k.lower()]
    for key in schedule_keys:
        if not validate_schedule_format(str(data.get(key, ''))):
            return jsonify({
                "status": "error",
                "message": f"Formato de horario inválido en '{key}'. Use HH:MM separado por comas."
            }), 400
    
    # Don't allow updating password via this endpoint if empty
    if 'smtp_pass' in data and data['smtp_pass'] == '':
        del data['smtp_pass']  # Keep existing password if empty
        changed_keys.remove('smtp_pass')
    
    cfg.update_settings(data)
    
    log_audit('settings_update', entity_type='settings', entity_name='system', 
              details={'keys_changed': changed_keys})
    
    return jsonify({"status": "ok", "message": "Settings updated"})

# ==========================
# Rate Limit with TTL Cache
# ==========================

class TTLCache:
    """Simple TTL cache for rate limiting. Auto-cleans expired entries."""
    
    def __init__(self, ttl_seconds=60, max_size=1000):
        self.ttl = ttl_seconds
        self.max_size = max_size
        self._cache = {}  # {key: (value, expiry_time)}
    
    def get(self, key, default=None):
        """Get value if exists and not expired."""
        import time
        if key in self._cache:
            value, expiry = self._cache[key]
            if time.time() < expiry:
                return value
            else:
                del self._cache[key]  # Cleanup expired
        return default
    
    def set(self, key, value):
        """Set value with TTL expiry."""
        import time
        # Cleanup if cache is too large
        if len(self._cache) >= self.max_size:
            self._cleanup()
        self._cache[key] = (value, time.time() + self.ttl)
    
    def _cleanup(self):
        """Remove expired entries."""
        import time
        now = time.time()
        expired = [k for k, (v, exp) in self._cache.items() if exp <= now]
        for k in expired:
            del self._cache[k]


# Rate limit store for test-email (with TTL to avoid memory leak)
_test_email_cooldown = TTLCache(ttl_seconds=120, max_size=1000)

@app.route('/api/settings/test-email', methods=['POST'])
@requires_auth
@requires_permission('test_email')
def api_test_email():
    """
    Send a test email to verify SMTP configuration.
    Rate limited: 1 request per 60 seconds per user.
    """
    import time
    from core.notifier import Notifier
    
    # Use get_current_user() for fresh data from DB
    user = get_current_user()
    user_id = user.get('username', 'anonymous') if user else 'anonymous'
    user_role = user.get('role', 'unknown') if user else 'unknown'
    client_ip = request.remote_addr
    
    # Rate limit check (60 seconds cooldown)
    now = time.time()
    last_request = _test_email_cooldown.get(user_id, 0)
    if now - last_request < 60:
        remaining = int(60 - (now - last_request))
        log.warning(f"Test email rate limited: user={user_id} ip={client_ip}")
        return jsonify({
            "status": "error", 
            "message": f"Esperá {remaining} segundos antes de volver a enviar un email de prueba."
        }), 429
    
    # Update cooldown
    _test_email_cooldown.set(user_id, now)
    
    # Send test email
    notifier = Notifier()
    success, message = notifier.send_test_email()
    
    # Audit with result
    log_audit('email_test', entity_type='email', entity_name='test_email',
              details={'result': 'success' if success else 'error', 'message': message})
    
    if success:
        return jsonify({"status": "ok", "message": message})
    else:
        return jsonify({"status": "error", "message": message}), 400

# ==========================
# ADMIN: USERS
# ==========================

@app.route('/admin/users')
@requires_auth
@requires_permission('manage_users')
def admin_users():
    cfg = get_config_manager()
    users = cfg.get_all_users()
    roles = cfg.get_all_roles()
    return render_template('users.html', users=users, roles=roles)

@app.route('/api/users', methods=['GET'])
@requires_auth
@requires_permission('manage_users')
def api_get_users():
    cfg = get_config_manager()
    return jsonify(cfg.get_all_users())

@app.route('/api/users', methods=['POST'])
@requires_auth
@requires_permission('manage_users')
def api_create_user():
    cfg = get_config_manager()
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    email = data.get('email', '').strip()
    role = data.get('role', 'viewer')
    permissions = data.get('permissions')  # List of permissions
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    user_id = cfg.create_user(username, password, role, email, permissions)
    if user_id:
        log_audit('user_create', entity_type='user', entity_id=str(user_id), entity_name=username, 
                  details={'role': role})
        return jsonify({"status": "ok", "id": user_id})
    return jsonify({"error": "User already exists"}), 400

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@requires_auth
@requires_permission('manage_users')
def api_update_user(user_id):
    cfg = get_config_manager()
    data = request.json
    
    # Get current user and target user for AUDIT
    current_user = get_current_user()
    actor_username = current_user.get('username', 'unknown') if current_user else 'unknown'
    client_ip = request.remote_addr
    
    target_user = cfg.get_user_by_id(user_id)
    if not target_user:
        return jsonify({"error": "User not found"}), 404
    
    target_username = target_user.get('username', 'unknown')
    old_role = target_user.get('role', 'unknown')
    new_role = data.get('role', old_role)
    
    # HARDENING: Block privilege escalation to superadmin
    # Only superadmin can assign superadmin role
    if new_role == 'superadmin':
        actor_perms = get_effective_permissions(current_user)
        if 'manage_roles' not in actor_perms:
            log.warning(f"AUDIT: BLOCKED privilege_escalation user={actor_username} ip={client_ip} "
                       f"target={target_username} attempted_role=superadmin")
            return jsonify({
                "error": "Solo superadmin puede asignar rol superadmin"
            }), 403
    
    # Don't allow updating password to empty
    password = data.get('password')
    if password == '':
        password = None
    
    cfg.update_user(
        user_id,
        username=data.get('username'),
        password=password,
        email=data.get('email'),
        role=new_role,
        active=data.get('active'),
        permissions=data.get('permissions')  # List of permissions
    )
    
    # AUDIT log for password change
    if password:
        log_audit('auth_password_change', entity_type='user', entity_id=str(user_id), 
                  entity_name=target_username, details={'changed_by': 'admin'})
    
    # AUDIT log for role changes
    if old_role != new_role:
        log_audit('user_update', entity_type='user', entity_id=str(user_id), entity_name=target_username,
                  details={'role_change': f'{old_role} -> {new_role}'})
    else:
        log_audit('user_update', entity_type='user', entity_id=str(user_id), entity_name=target_username)
    
    return jsonify({"status": "ok"})

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@requires_auth
@requires_permission('manage_users')
def api_delete_user(user_id):
    cfg = get_config_manager()
    
    # Get current user for AUDIT
    current_user = get_current_user()
    actor_username = current_user.get('username', 'unknown') if current_user else 'unknown'
    client_ip = request.remote_addr
    
    target_user = cfg.get_user_by_id(user_id)
    target_username = target_user.get('username', 'unknown') if target_user else 'unknown'
    
    # Prevent deleting user ID 1 (default admin)
    if user_id == 1:
        log.warning(f"AUDIT: BLOCKED delete_protected_user user={actor_username} ip={client_ip} target=admin")
        return jsonify({"error": "Cannot delete default admin"}), 400
    
    if cfg.delete_user(user_id):
        log_audit('user_delete', entity_type='user', entity_id=str(user_id), entity_name=target_username)
        return jsonify({"status": "ok"})
    return jsonify({"error": "User not found"}), 404

# ==========================
# API TOKENS
# ==========================

@app.route('/api/tokens', methods=['GET'])
@requires_auth
@requires_permission('manage_users')
def api_get_tokens():
    """List API tokens for current user (or all if superadmin)."""
    cfg = get_config_manager()
    
    # Use session-based auth (consistent with rest of app)
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Authentication required"}), 401
    
    user_id = current_user.get('id')
    username = current_user.get('username', 'unknown')
    
    # Superadmin can see all tokens, others only their own
    if has_permission(current_user, 'manage_roles'):
        tokens = cfg.get_all_tokens()
    else:
        tokens = cfg.get_user_tokens(user_id)
    
    log.debug(f"Token list: user={username} count={len(tokens) if tokens else 0}")
    return jsonify(tokens or [])

@app.route('/api/tokens', methods=['POST'])
@requires_auth
@requires_permission('manage_users')
def api_create_token():
    """Create a new API token for current user."""
    cfg = get_config_manager()
    
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Authentication required"}), 401
    
    user_id = current_user.get('id')
    username = current_user.get('username', 'unknown')
    client_ip = request.remote_addr
    
    data = request.json or {}
    name = data.get('name', 'API Token')
    expires_days = data.get('expires_days')
    
    token = cfg.create_api_token(user_id, name, expires_days)
    if token:
        log.info(f"AUDIT: token_create user={username} ip={client_ip} token_name={name}")
        return jsonify({"status": "ok", "token": token})
    
    log.warning(f"AUDIT: token_create_failed user={username} ip={client_ip}")
    return jsonify({"error": "Failed to create token"}), 500

@app.route('/api/tokens/<int:token_id>', methods=['DELETE'])
@requires_auth
@requires_permission('manage_users')
def api_delete_token(token_id):
    """Delete an API token."""
    cfg = get_config_manager()
    
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Authentication required"}), 401
    
    user_id = current_user.get('id')
    username = current_user.get('username', 'unknown')
    client_ip = request.remote_addr
    
    # Only allow deleting own tokens unless superadmin
    owner_id = user_id if not has_permission(current_user, 'manage_roles') else None
    
    if cfg.delete_api_token(token_id, owner_id):
        log.info(f"AUDIT: token_delete user={username} ip={client_ip} token_id={token_id}")
        return jsonify({"status": "ok"})
    
    log.warning(f"AUDIT: token_delete_failed user={username} ip={client_ip} token_id={token_id}")
    return jsonify({"error": "Token not found or access denied"}), 404

# ==========================
# ADMIN: ROLES
# ==========================

@app.route('/admin/roles')
@requires_auth
@requires_permission('manage_roles')
def admin_roles():
    cfg = get_config_manager()
    roles = cfg.get_all_roles()
    return render_template('roles.html', roles=roles, permissions_catalog=PERMISSIONS_CATALOG)

@app.route('/api/roles', methods=['GET'])
@requires_auth
@requires_permission('manage_roles')
def api_get_roles():
    cfg = get_config_manager()
    return jsonify(cfg.get_all_roles())

@app.route('/api/roles', methods=['POST'])
@requires_auth
@requires_permission('manage_roles')
def api_create_role():
    cfg = get_config_manager()
    data = request.json
    name = data.get('name', '').strip().lower()
    emoji = data.get('emoji', '👤')
    description = data.get('description', '')
    permissions = data.get('permissions', [])
    
    if not name:
        return jsonify({"error": "Nombre requerido"}), 400
    
    role_id = cfg.create_role(name, emoji, description, permissions)
    if role_id:
        log_audit('role_create', entity_type='role', entity_id=str(role_id), entity_name=name)
        return jsonify({"status": "ok", "id": role_id})
    return jsonify({"error": "El rol ya existe"}), 400

@app.route('/api/roles/<int:role_id>', methods=['PUT'])
@requires_auth
@requires_permission('manage_roles')
def api_update_role(role_id):
    cfg = get_config_manager()
    data = request.json
    
    # Check if removing manage_users from superadmin when only 1 exists
    role = cfg.get_role_by_id(role_id)
    if role and role.get('name') == 'superadmin':
        new_perms = data.get('permissions', [])
        if 'manage_users' not in new_perms or 'manage_roles' not in new_perms:
            return jsonify({"error": "El rol superadmin debe mantener permisos de gestión"}), 400
    
    cfg.update_role(
        role_id,
        name=data.get('name'),
        emoji=data.get('emoji'),
        description=data.get('description'),
        permissions=data.get('permissions')
    )
    log_audit('role_update', entity_type='role', entity_id=str(role_id), 
              entity_name=data.get('name') or (role.get('name') if role else 'unknown'))
    return jsonify({"status": "ok"})

@app.route('/api/roles/<int:role_id>', methods=['DELETE'])
@requires_auth
@requires_permission('manage_roles')
def api_delete_role(role_id):
    cfg = get_config_manager()
    role = cfg.get_role_by_id(role_id)
    role_name = role.get('name') if role else 'unknown'
    success, message = cfg.delete_role(role_id)
    if success:
        log_audit('role_delete', entity_type='role', entity_id=str(role_id), entity_name=role_name)
        return jsonify({"status": "ok", "message": message})
    return jsonify({"error": message}), 400

# ==========================
# CATALOG: DEVICE TYPES
# ==========================

@app.route('/admin/tipos')
@requires_auth
@requires_permission('view_inventory')
def tipos_page():
    """Show device types management page."""
    return render_template('tipos.html')

@app.route('/api/device_types')
@requires_auth
def api_get_device_types():
    db = get_db()
    return jsonify(db.get_device_types())

@app.route('/api/device_types', methods=['POST'])
@requires_auth
@requires_permission('edit_inventory')
def api_create_device_type():
    data = request.json
    type_id = data.get('id', '').strip().lower().replace(' ', '_')
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    
    if not type_id or not name:
        return jsonify({"error": "ID y nombre son requeridos"}), 400
    
    db = get_db()
    if db.create_device_type(type_id, name, description):
        return jsonify({"status": "ok"})
    return jsonify({"error": "El tipo ya existe"}), 400

@app.route('/api/device_types/<type_id>', methods=['PUT'])
@requires_auth
@requires_permission('edit_inventory')
def api_update_device_type(type_id):
    data = request.json
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    
    if not name:
        return jsonify({"error": "Nombre es requerido"}), 400
    
    db = get_db()
    if db.update_device_type(type_id, name, description):
        return jsonify({"status": "ok"})
    return jsonify({"error": "Tipo no encontrado"}), 404

@app.route('/api/device_types/<type_id>', methods=['DELETE'])
@requires_auth
@requires_permission('edit_inventory')
def api_delete_device_type(type_id):
    db = get_db()
    if db.delete_device_type(type_id):
        return jsonify({"status": "ok"})
    return jsonify({"error": "Tipo no encontrado"}), 404

# ==========================
# CATALOG: DEVICE MODELS
# ==========================

@app.route('/admin/modelos')
@app.route('/admin/tipos')
@app.route('/inventory/vendors')
@requires_auth
@requires_permission('view_inventory')
def vendors_page():
    """Show vendors and models management page (unified)."""
    return render_template('vendors.html')

@app.route('/api/device_models')
@requires_auth
def api_get_device_models():
    vendor = request.args.get('vendor')
    db = get_db()
    return jsonify(db.get_device_models(vendor))

@app.route('/api/device_models', methods=['POST'])
@requires_auth
@requires_permission('edit_inventory')
def api_create_device_model():
    data = request.json
    model_id = data.get('id', '').strip().lower().replace(' ', '_')
    name = data.get('name', '').strip()
    vendor = data.get('vendor', '').strip()
    description = data.get('description', '').strip()
    
    if not model_id or not name or not vendor:
        return jsonify({"error": "ID, nombre y vendor son requeridos"}), 400
    
    db = get_db()
    if db.create_device_model(model_id, name, vendor, description):
        return jsonify({"status": "ok"})
    return jsonify({"error": "El modelo ya existe"}), 400

@app.route('/api/device_models/<model_id>', methods=['PUT'])
@requires_auth
@requires_permission('edit_inventory')
def api_update_device_model(model_id):
    data = request.json
    name = data.get('name', '').strip()
    vendor = data.get('vendor', '').strip()
    description = data.get('description', '').strip()
    dev_type = data.get('type', '').strip()
    
    if not name or not vendor:
        return jsonify({"error": "Nombre y vendor son requeridos"}), 400
    
    db = get_db()
    if db.update_device_model(model_id, name, vendor, description, dev_type):
        return jsonify({"status": "ok"})
    return jsonify({"error": "Modelo no encontrado"}), 404

@app.route('/api/device_models/<model_id>', methods=['DELETE'])
@requires_auth
@requires_permission('edit_inventory')
def api_delete_device_model(model_id):
    db = get_db()
    if db.delete_device_model(model_id):
        return jsonify({"status": "ok"})
    return jsonify({"error": "Modelo no encontrado"}), 404

# ==========================
# API: TAGS AUTOCOMPLETE
# ==========================

@app.route('/api/tags')
@requires_auth
def api_get_tags():
    """Get unique tags from all devices."""
    inv = load_inventory()
    tags = set()
    for group in inv.get('groups', []):
        for device in group.get('devices', []):
            for tag in device.get('tags', []):
                tags.add(tag)
    return jsonify(sorted(list(tags)))


@app.route('/api/tags/suggestions')
@requires_auth
def api_get_tag_suggestions():
    """Get tag suggestions based on vendor and/or model context.
    
    Query params:
    - vendor: filter by vendor
    - model: filter by model (modelo field)
    
    Returns tags used by similar devices, ranked by frequency.
    """
    vendor_filter = request.args.get('vendor', '').lower()
    model_filter = request.args.get('model', '').lower()
    
    inv = load_inventory()
    tag_counts = {}
    
    for group in inv.get('groups', []):
        group_vendor = group.get('vendor', '').lower()
        
        for device in group.get('devices', []):
            device_model = str(device.get('modelo', '')).lower()
            
            # Match by vendor or model
            matches = False
            if model_filter and device_model == model_filter:
                matches = True
            elif vendor_filter and group_vendor == vendor_filter:
                matches = True
            
            if matches:
                for tag in device.get('tags', []):
                    tag_counts[tag] = tag_counts.get(tag, 0) + 1
    
    # Sort by frequency (most used first)
    sorted_tags = sorted(tag_counts.items(), key=lambda x: -x[1])
    
    # Return tags with their counts
    return jsonify([{"tag": t, "count": c} for t, c in sorted_tags[:15]])

# ==========================
# CATALOG: LOCALIDADES
# ==========================

ZONAS = ['Troncal Norte', 'Troncal Sur', 'Troncal Este', 'Troncal Oeste', 'Troncal Central']

@app.route('/api/zonas')
@requires_auth
def api_get_zonas():
    """Get available zonas."""
    return jsonify(ZONAS)

@app.route('/admin/localidades')
@app.route('/inventory/localidades')
@requires_auth
@requires_permission('view_inventory')
def localidades_page():
    """Show localidades management page."""
    return render_template('localidades.html')

@app.route('/api/localidades')
@requires_auth
def api_get_localidades():
    zona = request.args.get('zona')
    db = get_db()
    return jsonify(db.get_localidades(zona))

@app.route('/api/localidades', methods=['POST'])
@requires_auth
@requires_permission('edit_inventory')
def api_create_localidad():
    data = request.json
    loc_id = data.get('id', '').strip().lower().replace(' ', '_')
    name = data.get('name', '').strip()
    zona = data.get('zona', '').strip()
    
    if not loc_id or not name:
        return jsonify({"error": "ID y nombre son requeridos"}), 400
    
    db = get_db()
    if db.create_localidad(loc_id, name, zona):
        return jsonify({"status": "ok"})
    return jsonify({"error": "La localidad ya existe"}), 400

@app.route('/api/localidades/<loc_id>', methods=['PUT'])
@requires_auth
@requires_permission('edit_inventory')
def api_update_localidad(loc_id):
    data = request.json
    name = data.get('name', '').strip()
    zona = data.get('zona', '').strip()
    
    if not name:
        return jsonify({"error": "Nombre es requerido"}), 400
    
    db = get_db()
    if db.update_localidad(loc_id, name, zona):
        return jsonify({"status": "ok"})
    return jsonify({"error": "Localidad no encontrada"}), 404

@app.route('/api/localidades/<loc_id>', methods=['DELETE'])
@requires_auth
@requires_permission('edit_inventory')
def api_delete_localidad(loc_id):
    db = get_db()
    if db.delete_localidad(loc_id):
        return jsonify({"status": "ok"})
    return jsonify({"error": "Localidad no encontrada"}), 404

# ==========================
# API: DEPENDENCIES (for delete confirmation)
# ==========================

@app.route('/api/dependencies/<entity>/<path:entity_id>')
@requires_auth
def api_get_dependencies(entity, entity_id):
    """Get dependencies for an entity before deletion."""
    inv = load_inventory()
    db = get_db()
    result = {"entity": entity, "id": entity_id, "dependencies": [], "count": 0}
    
    if entity == "localidad":
        # Count devices using this localidad
        devices = []
        for group in inv.get('groups', []):
            for device in group.get('devices', []):
                if device.get('localidad') == entity_id:
                    devices.append({"sysname": device.get('sysname', device.get('hostname')), "group": group.get('name')})
        result["count"] = len(devices)
        result["dependencies"] = devices[:10]  # Limit to 10
        result["warning"] = f"{len(devices)} dispositivo(s) usan esta localidad"
        
    elif entity == "credencial":
        # Count groups using this credential
        groups = []
        for group in inv.get('groups', []):
            if entity_id in group.get('credential_ids', []):
                groups.append({"name": group.get('name'), "device_count": len(group.get('devices', []))})
        result["count"] = len(groups)
        result["dependencies"] = groups
        result["warning"] = f"{len(groups)} grupo(s) usan esta credencial"
        
    elif entity == "rol":
        # Count users with this role
        users = db.get_all_users()
        role_users = [u for u in users if u.get('role') == entity_id]
        result["count"] = len(role_users)
        result["dependencies"] = [{"username": u.get('username')} for u in role_users[:10]]
        result["warning"] = f"{len(role_users)} usuario(s) tienen este rol"
        
    elif entity == "modelo":
        # Count devices using this model
        devices = []
        for group in inv.get('groups', []):
            for device in group.get('devices', []):
                if device.get('modelo') == entity_id:
                    devices.append({"sysname": device.get('sysname', device.get('hostname')), "group": group.get('name')})
        result["count"] = len(devices)
        result["dependencies"] = devices[:10]
        result["warning"] = f"{len(devices)} dispositivo(s) usan este modelo"
        
    elif entity == "tipo":
        # Count models using this type
        models = db.get_device_models()
        type_models = [m for m in models if m.get('type') == entity_id]
        result["count"] = len(type_models)
        result["dependencies"] = [{"id": m.get('id'), "name": m.get('name')} for m in type_models[:10]]
        result["warning"] = f"{len(type_models)} modelo(s) usan este tipo"
        
    elif entity == "grupo":
        # Get device count for the group
        for group in inv.get('groups', []):
            if group.get('name') == entity_id:
                devices = group.get('devices', [])
                result["count"] = len(devices)
                result["dependencies"] = [{"sysname": d.get('sysname', d.get('hostname')), "ip": d.get('ip')} for d in devices[:10]]
                result["warning"] = f"{len(devices)} dispositivo(s) en este grupo"
                break
                
    elif entity == "dispositivo":
        # entity_id format: "group/sysname"
        parts = entity_id.split('/', 1)
        if len(parts) == 2:
            group_name, sysname = parts
            
            # Find vendor for this group
            vendor = None
            for group in inv.get('groups', []):
                if group.get('name') == group_name:
                    vendor = group.get('vendor')
                    break
            
            # Count backup files - use ARCHIVE_DIR where backups are actually stored
            import os
            backup_count = 0
            backup_files = []
            device_path = None
            
            # Try with vendor from group
            if vendor:
                device_path = os.path.join(ARCHIVE_DIR, vendor, sysname)
            
            # If not found with vendor, search in all vendor directories
            if not device_path or not os.path.exists(device_path):
                if os.path.exists(ARCHIVE_DIR):
                    for v in os.listdir(ARCHIVE_DIR):
                        test_path = os.path.join(ARCHIVE_DIR, v, sysname)
                        if os.path.exists(test_path) and os.path.isdir(test_path):
                            device_path = test_path
                            vendor = v
                            break
            
            if device_path and os.path.exists(device_path):
                for f in os.listdir(device_path):
                    if os.path.isfile(os.path.join(device_path, f)):
                        backup_count += 1
                        if len(backup_files) < 5:
                            backup_files.append(f)
            
            result["count"] = backup_count
            result["dependencies"] = backup_files
            result["vendor"] = vendor
            result["download_url"] = f"/files/{vendor}/{sysname}" if backup_count > 0 and vendor else None
            result["warning"] = f"{backup_count} archivo(s) de backup serán eliminados"
    
    return jsonify(result)

# ===========================================
# AUDIT LOG API
# ===========================================

@app.route('/admin/audit')
@requires_auth
@requires_permission('view_logs')
def audit_page():
    """Página de Registro de Auditoría."""
    return render_template('audit.html')

@app.route('/api/audit')
@requires_auth
@requires_permission('view_logs')
def api_get_audit_logs():
    """Get audit logs with pagination and filters."""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    # Build filters from query params
    filters = {}
    if request.args.get('event_type'):
        filters['event_type'] = request.args.get('event_type')
    if request.args.get('user_id'):
        filters['user_id'] = request.args.get('user_id', type=int)
    if request.args.get('username'):
        filters['username'] = request.args.get('username')
    if request.args.get('ip_address'):
        filters['ip_address'] = request.args.get('ip_address')
    if request.args.get('date_from'):
        filters['date_from'] = request.args.get('date_from')
    if request.args.get('date_to'):
        filters['date_to'] = request.args.get('date_to')
    if request.args.get('entity_type'):
        filters['entity_type'] = request.args.get('entity_type')
    if request.args.get('search'):
        filters['search'] = request.args.get('search')
    
    db = DBManager()
    logs = db.get_audit_logs(page=page, per_page=per_page, filters=filters if filters else None)
    total = db.get_audit_log_count(filters=filters if filters else None)
    
    return jsonify({
        'logs': logs,
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': (total + per_page - 1) // per_page
    })

@app.route('/api/audit/event-types')
@requires_auth
@requires_permission('view_logs')
def api_get_audit_event_types():
    """Get list of available event types for filtering."""
    # Return all defined categories plus any used in DB
    db = DBManager()
    db_types = db.get_audit_event_types()
    all_types = list(set(list(AUDIT_CATEGORIES.keys()) + db_types))
    all_types.sort()
    return jsonify(all_types)

@app.route('/api/audit/users')
@requires_auth
@requires_permission('view_logs')
def api_get_audit_users():
    """Get list of users that appear in audit logs."""
    db = DBManager()
    return jsonify(db.get_audit_users())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

