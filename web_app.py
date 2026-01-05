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
MAX_LOGIN_ATTEMPTS = 5
LOGIN_BLOCK_DURATION = 300  # 5 minutes

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
                   'test_email', 'manage_users', 'manage_roles']
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
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
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

def run_backup_async(group=None, device=None):
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
        engine.run(target_group=group, target_device=device)
        
        if backup_status["cancelled"]:
            backup_status["message"] = "Cancelado por usuario"
            backup_status["logs"].append({"type": "warning", "msg": "Proceso cancelado por usuario"})
        else:
            errors = len(backup_status["errors"])
            completed = len(backup_status["completed"])
            backup_status["message"] = f"Completado: {completed} OK, {errors} errores"
            backup_status["progress"] = 100
            backup_status["logs"].append({"type": "success", "msg": f"Finalizado: {completed} exitosos, {errors} fallidos"})
        
        backup_status["running"] = False
        
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
    device = request.args.get('device')
    
    thread = threading.Thread(target=run_backup_async, args=(group, device), daemon=True)
    thread.start()
    
    target = device or group or "Todos"
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
    
    # Load localidades catalog for troncales (zonas)
    try:
        catalogs = load_catalogs()
        troncales = set(loc.get('zona', '') for loc in catalogs.get('localidades', []) if loc.get('zona'))
    except Exception:
        troncales = set()
    
    localidades = set()
    tipos = set()
    vendors = set()
    grupos = set()
    tags = set()
    modelos = set()
    
    for group in inv.get('groups', []):
        grupos.add(group.get('name', ''))
        vendors.add(group.get('vendor', ''))
        
        for device in group.get('devices', []):
            if device.get('localidad'):
                localidades.add(device['localidad'])
            if device.get('tipo'):
                tipos.add(device['tipo'])
            if device.get('modelo'):
                modelos.add(device['modelo'])
            for tag in device.get('tags', []):
                tags.add(tag)
    
    return jsonify({
        'localidades': sorted(list(localidades)),
        'tipos': sorted(list(tipos)),
        'vendors': sorted(list(vendors)),
        'grupos': sorted(list(grupos)),
        'troncales': sorted(list(troncales)),  # From localidades zonas
        'modelos': sorted(list(modelos)),
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
    
    if not name or not vendor:
        return jsonify({"error": "Nombre y vendor son requeridos"}), 400
    
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
    
    # Audit log
    current_user = get_current_user()
    username = current_user.get('username', 'unknown') if current_user else 'unknown'
    log.info(f"AUDIT: inventory_group_create user={username} ip={request.remote_addr} group={name}")
    
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
            return jsonify({"status": "ok", "message": "Grupo actualizado"})
    return jsonify({"error": "Grupo no encontrado"}), 404

@app.route('/api/inventory/group/<group_name>', methods=['DELETE'])
@requires_auth
@requires_permission('edit_inventory')
def api_delete_group(group_name):
    """Delete a group and all its devices."""
    inv = load_inventory()
    original_len = len(inv.get("groups", []))
    inv["groups"] = [g for g in inv.get("groups", []) if g["name"] != group_name]
    
    # Audit log
    current_user = get_current_user()
    username = current_user.get('username', 'unknown') if current_user else 'unknown'
    
    if len(inv["groups"]) < original_len:
        save_inventory(inv)
        log.info(f"AUDIT: inventory_group_delete user={username} ip={request.remote_addr} group={group_name} result=OK")
        return jsonify({"status": "ok", "message": "Grupo eliminado"})
    
    log.info(f"AUDIT: inventory_group_delete user={username} ip={request.remote_addr} group={group_name} result=NOT_FOUND")
    return jsonify({"error": "Grupo no encontrado"}), 404

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
    
    # Get current user for audit
    current_user = get_current_user()
    username = current_user.get('username', 'unknown') if current_user else 'unknown'
    client_ip = request.remote_addr
    
    success, message = add_credential(cred_id, name, user, password, extra_pass)
    
    # Audit log (no secrets)
    result_str = "OK" if success else "ERROR"
    log.info(f"AUDIT: vault_create user={username} ip={client_ip} cred_id={cred_id} result={result_str}")
    
    if success:
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
    
    # Get current user for audit
    current_user = get_current_user()
    username = current_user.get('username', 'unknown') if current_user else 'unknown'
    client_ip = request.remote_addr
    
    success, message = update_credential(cred_id, name, user, password, extra_pass)
    
    # Audit log (no secrets)
    result_str = "OK" if success else "ERROR"
    log.info(f"AUDIT: vault_update user={username} ip={client_ip} cred_id={cred_id} result={result_str}")
    
    if success:
        return jsonify({"status": "ok", "message": message})
    return jsonify({"error": message}), 404

@app.route('/api/vault/<cred_id>', methods=['DELETE'])
@requires_auth
@requires_permission('edit_vault')
def api_delete_vault_credential(cred_id):
    """Delete a credential from vault."""
    from core.vault import delete_credential
    
    # Get current user for audit
    current_user = get_current_user()
    username = current_user.get('username', 'unknown') if current_user else 'unknown'
    client_ip = request.remote_addr
    
    success, message = delete_credential(cred_id)
    
    # Audit log
    result_str = "OK" if success else "ERROR"
    log.info(f"AUDIT: vault_delete user={username} ip={client_ip} cred_id={cred_id} result={result_str}")
    
    if success:
        return jsonify({"status": "ok", "message": message})
    return jsonify({"error": message}), 404

# ==========================
# ADMIN PAGE: VAULT
# ==========================

@app.route('/admin/vault')
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
    
    # Keep sysname immutable
    original_sysname = device_data.get("sysname") or device_data.get("hostname")
    device_data["sysname"] = original_sysname
    device_data["hostname"] = original_sysname  # Compatibility
    
    # Update mutable fields
    if new_ip:
        device_data["ip"] = new_ip
    
    # Update optional fields
    for field in ["nombre", "localidad", "tipo", "modelo", "criticidad"]:
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
    
    # Add to target group (same or different)
    for g in inv["groups"]:
        if g["name"] == new_group:
            g["devices"].append(device_data)
            save_inventory(inv)
            return jsonify({"status": "ok", "message": "Dispositivo actualizado"})
    
    # If target group not found, put back in original
    for g in inv["groups"]:
        if g["name"] == group_name:
            g["devices"].append(device_data)
    save_inventory(inv)
    return jsonify({"error": "Grupo destino no encontrado"}), 404

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
    
    # Helper to safe list directory
    def list_dir_safe(path, relative_to):
        target = os.path.abspath(os.path.join(base, path))
        if not target.startswith(os.path.abspath(base)):
            return jsonify({"error": "Access denied"}), 403
        if not os.path.exists(target):
            return jsonify({"error": "Path not found"}), 404
        items = []
        for entry in os.scandir(target):
            items.append({
                "name": entry.name,
                "is_dir": entry.is_dir(),
                "size": entry.stat().st_size if entry.is_file() else 0,
                "mtime": datetime.fromtimestamp(entry.stat().st_mtime).isoformat()
            })
        return jsonify({"path": relative_to, "items": sorted(items, key=lambda x: (not x["is_dir"], x["name"]))})

    if view == 'physical':
        # Default physical browsing (Group/Device/Files)
        return list_dir_safe(subpath, subpath)

    # Virtual Views Logic
    parts = subpath.split('/') if subpath else []
    
    # helper to get categories from inventory
    def get_categories(key):
        inv = load_inventory()
        cats = set()
        for g in inv.get('groups', []):
            if key == 'vendor': 
                cats.add(g.get('vendor', 'Unknown'))
            else:
                for d in g.get('devices', []):
                    val = d.get(key)
                    if val: cats.add(val)
        return sorted(list(cats))
        
    # helper to get devices in category
    def get_devices(cat_key, cat_val):
        inv = load_inventory()
        devices = []
        for g in inv.get('groups', []):
            g_vendor = g.get('vendor', '').lower()
            for d in g.get('devices', []):
                match = False
                if cat_key == 'vendor': match = g_vendor == cat_val.lower()
                else: match = (d.get(cat_key) or '').lower() == cat_val.lower()
                
                if match:
                    devices.append(d.get('sysname') or d.get('hostname'))
        return sorted(list(set(devices)))

    # ROOT: List categories (virtual folders)
    if not parts:
        cats = []
        if view == 'localidad': cats = get_categories('localidad')
        elif view == 'tipo': cats = get_categories('tipo')
        elif view == 'vendor': cats = get_categories('vendor')
        
        return jsonify({
            "path": "",
            "items": [{"name": c, "is_dir": True, "size": 0, "mtime": datetime.now().isoformat()} for c in cats]
        })

    # LEVEL 1: Category selected -> List devices (virtual folders)
    category = parts[0]
    if len(parts) == 1:
        devices = get_devices(view, category)
        return jsonify({
            "path": category,
            "items": [{"name": d, "is_dir": True, "size": 0, "mtime": datetime.now().isoformat()} for d in devices]
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
                # vendor_name comes from group's vendor (lowercased, as used by engine)
                vendor_name = g.get('vendor', '').lower()
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
    target = os.path.abspath(os.path.join(base, filepath))
    if not target.startswith(os.path.abspath(base)):
        return jsonify({"error": "Access denied"}), 403
    
    if not os.path.isfile(target):
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
    
    repo_file = os.path.join(REPO_DIR, vendor, f"{hostname}.cfg")
    if not os.path.exists(repo_file):
        # Try alternative extensions
        for ext in ['.txt', '.dat', '']:
            alt = os.path.join(REPO_DIR, vendor, f"{hostname}{ext}")
            if os.path.exists(alt):
                repo_file = alt
                break
        else:
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
            cwd=REPO_DIR, capture_output=True, text=True
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
    
    # 3. Filter by localidad/troncal/tipo/grupo/criticidad requires inventory lookup
    localidad = request.args.get('localidad')
    troncal = request.args.get('troncal')
    tipo = request.args.get('tipo')
    grupo = request.args.get('grupo')
    criticidad = request.args.get('criticidad')
    
    # If any inventory-based filter, load inventory and catalogs
    if localidad or troncal or tipo or grupo or criticidad:
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
                    
                if match:
                    matching_hosts.append(device.get('sysname') or device.get('hostname'))
        
        filters['hostname_in'] = matching_hosts

    db = get_db()
    
    # Get total and jobs
    total = db.get_jobs_count(filters)
    raw_jobs = db.get_jobs(page, per_page, filters)
    
    # Format for API
    jobs = []
    for row in raw_jobs:
        jobs.append({
            "id": row['id'], 
            "hostname": row['hostname'], 
            "vendor": row['vendor'], 
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
    return send_from_directory(os.path.dirname(safe_path), os.path.basename(safe_path), as_attachment=True)

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
    
    # Audit log (no values, only keys changed)
    log.info(f"AUDIT: settings_update user={username} ip={request.remote_addr} keys={changed_keys}")
    
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
    
    # Audit logging (sin credenciales)
    result_str = "OK" if success else "ERROR"
    log.info(f"AUDIT: test_email user={user_id} role={user_role} ip={client_ip} result={result_str}")
    
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
    
    # AUDIT log for role changes
    if old_role != new_role:
        log.info(f"AUDIT: user_role_change actor={actor_username} ip={client_ip} "
                f"target={target_username} old_role={old_role} new_role={new_role}")
    else:
        log.info(f"AUDIT: user_update actor={actor_username} ip={client_ip} target={target_username}")
    
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
        log.info(f"AUDIT: user_delete actor={actor_username} ip={client_ip} target={target_username}")
        return jsonify({"status": "ok"})
    return jsonify({"error": "User not found"}), 404

# ==========================
# API TOKENS
# ==========================

@app.route('/api/tokens', methods=['GET'])
@requires_auth
def api_get_tokens():
    cfg = get_config_manager()
    auth = request.authorization
    user = cfg.get_user(auth.username)
    if user:
        return jsonify(cfg.get_user_tokens(user['id']))
    return jsonify([])

@app.route('/api/tokens', methods=['POST'])
@requires_auth
def api_create_token():
    cfg = get_config_manager()
    auth = request.authorization
    user = cfg.get_user(auth.username)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    data = request.json or {}
    name = data.get('name', 'API Token')
    expires_days = data.get('expires_days')
    
    token = cfg.create_api_token(user['id'], name, expires_days)
    if token:
        return jsonify({"status": "ok", "token": token})
    return jsonify({"error": "Failed to create token"}), 500

@app.route('/api/tokens/<int:token_id>', methods=['DELETE'])
@requires_auth
def api_delete_token(token_id):
    cfg = get_config_manager()
    auth = request.authorization
    user = cfg.get_user(auth.username)
    
    if cfg.delete_api_token(token_id, user['id'] if user else None):
        return jsonify({"status": "ok"})
    return jsonify({"error": "Token not found"}), 404

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
    return jsonify({"status": "ok"})

@app.route('/api/roles/<int:role_id>', methods=['DELETE'])
@requires_auth
@requires_permission('manage_roles')
def api_delete_role(role_id):
    cfg = get_config_manager()
    success, message = cfg.delete_role(role_id)
    if success:
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
@requires_auth
@requires_permission('view_inventory')
def modelos_page():
    """Show device models management page."""
    return render_template('modelos.html')

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
    
    if not name or not vendor:
        return jsonify({"error": "Nombre y vendor son requeridos"}), 400
    
    db = get_db()
    if db.update_device_model(model_id, name, vendor, description):
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

# ==========================
# CATALOG: LOCALIDADES
# ==========================

ZONAS = ['Troncal Norte', 'Troncal Sur', 'Troncal Este', 'Troncal Oeste']

@app.route('/api/zonas')
@requires_auth
def api_get_zonas():
    """Get available zonas."""
    return jsonify(ZONAS)

@app.route('/admin/localidades')
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

