from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, abort, Response
import os
import shutil
import yaml
import json
import threading
import subprocess
from datetime import datetime, timedelta
from functools import wraps
from settings import BACKUP_ROOT_DIR, INVENTORY_FILE, DB_FILE, REPO_DIR, ARCHIVE_DIR
from core.db_manager import DBManager
from core.logger import log

app = Flask(__name__)
app.secret_key = 'super_secret_key_change_me'

# Global state for backup execution
backup_status = {"running": False, "message": "", "progress": 0}

# Basic Auth
USERS = {"admin": "noc4242"}

def check_auth(username, password):
    return username in USERS and USERS[username] == password

def authenticate():
    return jsonify({"message": "Authentication Required"}), 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

def get_db():
    return DBManager(DB_FILE)

# ==========================
# DASHBOARD
# ==========================

@app.route('/')
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
def backup_status_api():
    return jsonify(backup_status)

@app.route('/api/backup/cancel')
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
def admin_vault():
    """Credential vault management page."""
    from core.vault import get_credentials_list
    credentials = get_credentials_list()
    return render_template('vault.html', credentials=credentials)

@app.route('/api/inventory/device', methods=['POST'])
@requires_auth
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
def files_browser(subpath=""):
    return render_template('files.html', current_path=subpath)

@app.route('/diff/<vendor>/<hostname>')
def diff_page(vendor, hostname):
    return render_template('diff.html', vendor=vendor, hostname=hostname)

@app.route('/download/<path:filepath>')
def download_file(filepath):
    safe_path = os.path.abspath(os.path.join(ARCHIVE_DIR, filepath))
    if not safe_path.startswith(os.path.abspath(ARCHIVE_DIR)):
        return abort(403)
    if not os.path.exists(safe_path):
        return abort(404)
    return send_from_directory(os.path.dirname(safe_path), os.path.basename(safe_path), as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
