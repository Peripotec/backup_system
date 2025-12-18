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
    
    try:
        total, used, free = shutil.disk_usage(BACKUP_ROOT_DIR)
        disk_info = {
            "percent": round((used / total) * 100, 1),
            "free_gb": round(free / (1024**3), 2),
            "total_gb": round(total / (1024**3), 2)
        }
    except:
        disk_info = {"percent": 0, "free_gb": 0, "total_gb": 0}

    return render_template('dashboard.html', stats=stats, jobs=jobs, disk=disk_info, backup_status=backup_status)

# ==========================
# API: BACKUP TRIGGER
# ==========================

def run_backup_async(group=None):
    global backup_status
    backup_status = {"running": True, "message": "Iniciando backup...", "progress": 10}
    try:
        from core.engine import BackupEngine
        engine = BackupEngine(dry_run=False)
        backup_status["message"] = "Ejecutando backups..."
        backup_status["progress"] = 50
        engine.run(target_group=group)
        backup_status = {"running": False, "message": "Completado!", "progress": 100}
    except Exception as e:
        backup_status = {"running": False, "message": f"Error: {e}", "progress": 0}

@app.route('/api/backup/trigger', methods=['POST'])
@requires_auth
def trigger_backup():
    global backup_status
    if backup_status["running"]:
        return jsonify({"error": "Backup already running"}), 400
    
    group = request.json.get('group') if request.is_json else None
    thread = threading.Thread(target=run_backup_async, args=(group,))
    thread.start()
    return jsonify({"status": "started", "message": "Backup iniciado"})

@app.route('/api/backup/status')
def backup_status_api():
    return jsonify(backup_status)

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
    new_group = {
        "name": data.get("name"),
        "vendor": data.get("vendor"),
        "credentials": {
            "user": data.get("user"),
            "pass": data.get("pass"),
            "extra_pass": data.get("extra_pass", "")
        },
        "devices": []
    }
    inv["groups"].append(new_group)
    save_inventory(inv)
    return jsonify({"status": "ok", "message": "Grupo creado"})

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

# ==========================
# API: DIFF VIEWER
# ==========================

@app.route('/api/diff/<vendor>/<hostname>')
def api_get_diff(vendor, hostname):
    repo_path = os.path.join(REPO_DIR, vendor, f"{hostname}.cfg")
    if not os.path.exists(repo_path):
        return jsonify({"error": "File not in repo", "diff": ""})
    
    try:
        result = subprocess.run(
            ["git", "log", "-p", "-3", "--pretty=format:%H|%ai|%s", "--", f"{vendor}/{hostname}.cfg"],
            cwd=REPO_DIR, capture_output=True, text=True
        )
        return jsonify({"hostname": hostname, "diff": result.stdout})
    except Exception as e:
        return jsonify({"error": str(e), "diff": ""})

# ==========================
# API: STATS HISTORY
# ==========================

@app.route('/api/stats/history')
def api_stats_history():
    db = get_db()
    # Get last 7 days stats
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
    
    # Format for chart
    data = {}
    for day, status, count in rows:
        if day not in data:
            data[day] = {"SUCCESS": 0, "ERROR": 0}
        data[day][status] = count
    
    return jsonify(data)

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
