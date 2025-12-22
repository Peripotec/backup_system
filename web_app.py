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
    except:
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
              'edit_inventory', 'view_vault', 'edit_vault', 'view_settings', 'edit_settings'],
    'superadmin': ['view_dashboard', 'view_files', 'view_diff', 'run_backup', 'view_inventory', 
                   'edit_inventory', 'view_vault', 'edit_vault', 'view_settings', 'edit_settings',
                   'manage_users', 'manage_roles']
}

def has_permission(user_or_role, permission):
    """Check if user has a specific permission. Accepts user dict or role string."""
    if isinstance(user_or_role, dict):
        # User dict - check user's explicit permissions first
        user_perms = user_or_role.get('permissions', [])
        if user_perms:
            return permission in user_perms
        # Fallback to role defaults
        role = user_or_role.get('role', 'viewer')
        return permission in ROLE_PERMISSIONS.get(role, [])
    else:
        # Role string - use role defaults
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
    except:
        disk_info = {"percent": 0, "free_gb": 0, "total_gb": 0}

    return render_template('dashboard.html', stats=stats, jobs=jobs, disk=disk_info, backup_status=backup_status, inventory=inv)

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
    try:
        with open(INVENTORY_FILE, 'r') as f:
            return yaml.safe_load(f) or {"groups": []}
    except:
        return {"groups": []}

def save_inventory(data):
    with open(INVENTORY_FILE, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

@app.route('/api/inventory')
@requires_auth
def api_get_inventory():
    return jsonify(load_inventory())

@app.route('/api/inventory/group', methods=['POST'])
@requires_auth
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
    return jsonify({"status": "ok", "message": "Grupo creado"})

@app.route('/api/inventory/group/<group_name>', methods=['PUT'])
@requires_auth
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
def api_delete_group(group_name):
    """Delete a group and all its devices."""
    inv = load_inventory()
    original_len = len(inv.get("groups", []))
    inv["groups"] = [g for g in inv.get("groups", []) if g["name"] != group_name]
    if len(inv["groups"]) < original_len:
        save_inventory(inv)
        return jsonify({"status": "ok", "message": "Grupo eliminado"})
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
def api_get_vault():
    """Get all credentials (without passwords)."""
    from core.vault import get_credentials_list
    return jsonify(get_credentials_list())

@app.route('/api/vault', methods=['POST'])
@requires_auth
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
        return jsonify({"status": "ok", "message": message})
    return jsonify({"error": message}), 400

@app.route('/api/vault/<cred_id>', methods=['PUT'])
@requires_auth
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
        return jsonify({"status": "ok", "message": message})
    return jsonify({"error": message}), 404

@app.route('/api/vault/<cred_id>', methods=['DELETE'])
@requires_auth
def api_delete_vault_credential(cred_id):
    """Delete a credential from vault."""
    from core.vault import delete_credential
    success, message = delete_credential(cred_id)
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
    for g in inv["groups"]:
        if g["name"] == group_name:
            g["devices"].append({
                "hostname": data.get("hostname"),
                "ip": data.get("ip")
            })
            save_inventory(inv)
            return jsonify({"status": "ok", "message": "Dispositivo agregado"})
    return jsonify({"error": "Group not found"}), 404

@app.route('/api/inventory/device/<group_name>/<hostname>', methods=['DELETE'])
@requires_auth
def api_delete_device(group_name, hostname):
    inv = load_inventory()
    for g in inv["groups"]:
        if g["name"] == group_name:
            g["devices"] = [d for d in g["devices"] if d["hostname"] != hostname]
            save_inventory(inv)
            return jsonify({"status": "ok", "message": "Dispositivo eliminado"})
    return jsonify({"error": "Not found"}), 404

@app.route('/api/inventory/device/<group_name>/<hostname>', methods=['PUT'])
@requires_auth
def api_edit_device(group_name, hostname):
    """Edit an existing device. Supports moving to different group."""
    data = request.json
    inv = load_inventory()
    
    new_group = data.get("group", group_name)
    new_hostname = data.get("hostname", hostname)
    new_ip = data.get("ip")
    new_credential_ids = data.get("credential_ids")  # Optional device-level override
    
    # Find and remove device from original group
    device_data = None
    for g in inv["groups"]:
        if g["name"] == group_name:
            for i, d in enumerate(g["devices"]):
                if d["hostname"] == hostname:
                    device_data = g["devices"].pop(i)
                    break
            break
    
    if not device_data:
        return jsonify({"error": "Device not found"}), 404
    
    # Update device data
    device_data["hostname"] = new_hostname
    if new_ip:
        device_data["ip"] = new_ip
    if new_credential_ids is not None:
        if new_credential_ids:
            device_data["credential_ids"] = new_credential_ids
        elif "credential_ids" in device_data:
            del device_data["credential_ids"]  # Remove override if empty
    
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
    return jsonify({"error": "Target group not found"}), 404

@app.route('/api/inventory/test', methods=['POST'])
@requires_auth
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
    base = ARCHIVE_DIR
    target = os.path.abspath(os.path.join(base, subpath))
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
    return jsonify({"path": subpath, "items": sorted(items, key=lambda x: (not x["is_dir"], x["name"]))})

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
    except:
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
    """Get paginated jobs list."""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    offset = (page - 1) * per_page
    
    db = get_db()
    conn = db._get_connection()
    cursor = conn.cursor()
    
    # Get total count
    cursor.execute('SELECT COUNT(*) FROM jobs')
    total = cursor.fetchone()[0]
    
    # Get page of jobs
    cursor.execute('''
        SELECT id, hostname, vendor, group_name, status, message, timestamp, duration_seconds, changed
        FROM jobs 
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    ''', (per_page, offset))
    
    jobs = []
    for row in cursor.fetchall():
        jobs.append({
            "id": row[0], "hostname": row[1], "vendor": row[2], "group_name": row[3],
            "status": row[4], "message": row[5], "timestamp": row[6], 
            "duration": row[7], "changed": row[8]
        })
    
    conn.close()
    
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
    except:
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
    return render_template('settings.html', settings=settings)

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
    # Don't allow updating password via this endpoint
    if 'smtp_pass' in data and data['smtp_pass'] == '':
        del data['smtp_pass']  # Keep existing password if empty
    cfg.update_settings(data)
    return jsonify({"status": "ok", "message": "Settings updated"})

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
def api_update_user(user_id):
    cfg = get_config_manager()
    data = request.json
    
    # Don't allow updating password to empty
    password = data.get('password')
    if password == '':
        password = None
    
    cfg.update_user(
        user_id,
        username=data.get('username'),
        password=password,
        email=data.get('email'),
        role=data.get('role'),
        active=data.get('active'),
        permissions=data.get('permissions')  # List of permissions
    )
    return jsonify({"status": "ok"})

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@requires_auth
def api_delete_user(user_id):
    cfg = get_config_manager()
    # Prevent deleting user ID 1 (default admin)
    if user_id == 1:
        return jsonify({"error": "Cannot delete default admin"}), 400
    
    if cfg.delete_user(user_id):
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
    return render_template('roles.html', roles=roles)

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

