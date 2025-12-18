from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, abort
import os
import shutil
import yaml
import sqlite3
from functools import wraps
from settings import BACKUP_ROOT_DIR, INVENTORY_FILE, DB_FILE, LOG_DIR
from core.db_manager import DBManager
from core.logger import log

app = Flask(__name__)
app.secret_key = 'super_secret_key_change_me'

# Basic Auth (Very simple for MVP)
USERS = {
    "admin": "noc4242" # Placeholder
}

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

# Helper to get DB connection for Flask (Thread safe)
def get_db_stats():
    db = DBManager(DB_FILE)
    return db.get_stats_24h()

def get_recent_jobs(limit=50):
    db = DBManager(DB_FILE)
    return db.get_recent_jobs(limit)

# ==========================
# RUTAS
# ==========================

@app.route('/')
def index():
    """Dashboard principal."""
    stats = get_db_stats()
    jobs = get_recent_jobs()
    
    # Disk Usage
    try:
        total, used, free = shutil.disk_usage(BACKUP_ROOT_DIR)
        disk_percent = (used / total) * 100
        disk_info = {
            "percent": round(disk_percent, 1),
            "free_gb": round(free / (1024**3), 2),
            "total_gb": round(total / (1024**3), 2)
        }
    except:
        disk_info = {"percent": 0, "free_gb": 0, "total_gb": 0}

    return render_template('dashboard.html', stats=stats, jobs=jobs, disk=disk_info)

@app.route('/inventory', methods=['GET', 'POST'])
@requires_auth
def inventory():
    """Inventory Manager."""
    if request.method == 'POST':
        # Save YAML
        try:
            new_data = yaml.safe_load(request.form.get('yaml_content'))
            if not new_data:
                raise ValueError("Empty YAML")
            
            with open(INVENTORY_FILE, 'w') as f:
                yaml.dump(new_data, f, default_flow_style=False)
                
            return redirect(url_for('inventory'))
        except Exception as e:
            return f"Error saving YAML: {e}", 400

    # Load YAML
    try:
        with open(INVENTORY_FILE, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        content = "# Inventory file not found"
    
    return render_template('inventory.html', content=content)

@app.route('/files/<path:filepath>')
def download_file(filepath):
    """Serve files from BACKUP_ROOT_DIR."""
    # Security check
    safe_path = os.path.abspath(os.path.join(BACKUP_ROOT_DIR, filepath))
    if not safe_path.startswith(os.path.abspath(BACKUP_ROOT_DIR)):
        return abort(403)
        
    if not os.path.exists(safe_path):
        return abort(404)

    return send_from_directory(os.path.dirname(safe_path), os.path.basename(safe_path))

# Start
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
