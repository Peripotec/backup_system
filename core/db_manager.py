import sqlite3
import os
from datetime import datetime
from settings import DB_FILE
from core.logger import log

class DBManager:
    def __init__(self, db_path=DB_FILE):
        self.db_path = db_path
        self._check_init()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _check_init(self):
        """Initializes the database schema if it doesn't exist."""
        if not os.path.exists(self.db_path):
            log.info(f"Initializing new database at {self.db_path}")
        
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            
            # Table: Jobs (Execution history)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    hostname TEXT,
                    vendor TEXT,
                    group_name TEXT,
                    status TEXT, -- 'SUCCESS', 'ERROR', 'WARNING'
                    message TEXT,
                    file_path TEXT,
                    file_size INTEGER,
                    duration_seconds REAL,
                    changed BOOLEAN DEFAULT 0 -- For Git diffs
                )
            ''')
            
            # Table: Runs (Summary of a batch execution)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    end_time DATETIME,
                    total_devices INTEGER,
                    success_count INTEGER,
                    error_count INTEGER,
                    type TEXT -- 'MANUAL', 'CRON'
                )
            ''')
            
            # Table: Device Types (Catalog)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS device_types (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Table: Device Models (Catalog)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS device_models (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    vendor TEXT NOT NULL,
                    description TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Table: Localidades (Catalog)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS localidades (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    zona TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
        except Exception as e:
            log.error(f"Database initialization error: {e}")
            raise
        finally:
            conn.close()

    def record_job(self, hostname, vendor, group_name, status, message, file_path=None, file_size=0, duration=0, changed=False):
        """Records a single device backup job."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO jobs (timestamp, hostname, vendor, group_name, status, message, file_path, file_size, duration_seconds, changed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (datetime.now(), hostname, vendor, group_name, status, message, file_path, file_size, duration, changed))
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            log.error(f"Failed to record job for {hostname}: {e}")
        finally:
            conn.close()

    def start_run(self, run_type="CRON"):
        """Starts a batch run record."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO runs (start_time, type) VALUES (?, ?)
            ''', (datetime.now(), run_type))
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            log.error(f"Failed to start run: {e}")
            return None
        finally:
            conn.close()

    def end_run(self, run_id, total, success, errors):
        """Updates the batch run record with final stats."""
        if not run_id:
            return
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE runs 
                SET end_time = ?, total_devices = ?, success_count = ?, error_count = ?
                WHERE id = ?
            ''', (datetime.now(), total, success, errors, run_id))
            conn.commit()
        except Exception as e:
            log.error(f"Failed to end run {run_id}: {e}")
        finally:
            conn.close()

    def get_recent_jobs(self, limit=100):
        """Used by Dashboard."""
        conn = self._get_connection()
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM jobs ORDER BY id DESC LIMIT ?', (limit,))
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def get_stats_24h(self):
        """Returns success/error counts for the last 24h."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            # Simple query for now
            cursor.execute('''
                SELECT status, count(*) 
                FROM jobs 
                WHERE timestamp >= datetime('now', '-1 day')
                GROUP BY status
            ''')
            return dict(cursor.fetchall())
        finally:
            conn.close()

    # ========================
    # DEVICE TYPES CATALOG
    # ========================
    
    def get_device_types(self):
        """Get all device types."""
        conn = self._get_connection()
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM device_types ORDER BY name')
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()
    
    def get_device_type(self, type_id):
        """Get a single device type."""
        conn = self._get_connection()
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM device_types WHERE id = ?', (type_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()
    
    def create_device_type(self, type_id, name, description=''):
        """Create a device type."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO device_types (id, name, description) VALUES (?, ?, ?)',
                          (type_id, name, description))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()
    
    def update_device_type(self, type_id, name, description=''):
        """Update a device type."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('UPDATE device_types SET name = ?, description = ? WHERE id = ?',
                          (name, description, type_id))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()
    
    def delete_device_type(self, type_id):
        """Delete a device type."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM device_types WHERE id = ?', (type_id,))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    # ========================
    # DEVICE MODELS CATALOG
    # ========================
    
    def get_device_models(self, vendor=None):
        """Get device models, optionally filtered by vendor."""
        conn = self._get_connection()
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            if vendor:
                cursor.execute('SELECT * FROM device_models WHERE vendor = ? ORDER BY name', (vendor,))
            else:
                cursor.execute('SELECT * FROM device_models ORDER BY vendor, name')
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()
    
    def get_device_model(self, model_id):
        """Get a single device model."""
        conn = self._get_connection()
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM device_models WHERE id = ?', (model_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()
    
    def create_device_model(self, model_id, name, vendor, description=''):
        """Create a device model."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO device_models (id, name, vendor, description) VALUES (?, ?, ?, ?)',
                          (model_id, name, vendor, description))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()
    
    def update_device_model(self, model_id, name, vendor, description=''):
        """Update a device model."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('UPDATE device_models SET name = ?, vendor = ?, description = ? WHERE id = ?',
                          (name, vendor, description, model_id))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()
    
    def delete_device_model(self, model_id):
        """Delete a device model."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM device_models WHERE id = ?', (model_id,))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    # ========================
    # LOCALIDADES CATALOG
    # ========================
    
    def get_localidades(self, zona=None):
        """Get localidades, optionally filtered by zona."""
        conn = self._get_connection()
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            if zona:
                cursor.execute('SELECT * FROM localidades WHERE zona = ? ORDER BY name', (zona,))
            else:
                cursor.execute('SELECT * FROM localidades ORDER BY zona, name')
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()
    
    def create_localidad(self, loc_id, name, zona=''):
        """Create a localidad."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO localidades (id, name, zona) VALUES (?, ?, ?)',
                          (loc_id, name, zona))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()
    
    def update_localidad(self, loc_id, name, zona=''):
        """Update a localidad."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('UPDATE localidades SET name = ?, zona = ? WHERE id = ?',
                          (name, zona, loc_id))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()
    
    def delete_localidad(self, loc_id):
        """Delete a localidad."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM localidades WHERE id = ?', (loc_id,))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()
