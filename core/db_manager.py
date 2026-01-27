import sqlite3
import os
from datetime import datetime, timedelta
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
                    type TEXT, -- 'MANUAL', 'CRON'
                    triggered_by TEXT, -- 'CRON', 'MANUAL:username', 'API'
                    log_path TEXT -- Path to run log file
                )
            ''')
            
            # Migration: Add new columns if they don't exist (for existing DBs)
            try:
                cursor.execute('ALTER TABLE runs ADD COLUMN triggered_by TEXT')
            except:
                pass  # Column already exists
            try:
                cursor.execute('ALTER TABLE runs ADD COLUMN log_path TEXT')
            except:
                pass  # Column already exists
            
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
            
            # Table: Audit Log (Activity tracking - Bookstack style)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    user_id INTEGER,
                    username TEXT,
                    event_type TEXT NOT NULL,
                    event_category TEXT,
                    entity_type TEXT,
                    entity_id TEXT,
                    entity_name TEXT,
                    details TEXT,
                    ip_address TEXT,
                    user_agent TEXT
                )
            ''')
            
            # Indexes for audit_log performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_type, entity_id)')
            
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

    def record_job_start(self, hostname, vendor, group_name):
        """Record a job as IN_PROGRESS before execution starts."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO jobs (timestamp, hostname, vendor, group_name, status, message)
                VALUES (?, ?, ?, ?, 'IN_PROGRESS', 'Backup iniciado')
            ''', (datetime.now(), hostname, vendor, group_name))
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            log.error(f"Failed to record job start for {hostname}: {e}")
            return None
        finally:
            conn.close()

    def update_job_status(self, job_id, status, message, file_path=None, file_size=0, duration=0, changed=False):
        """Update an existing job record with final status."""
        if not job_id:
            return
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE jobs 
                SET status = ?, message = ?, file_path = ?, file_size = ?, 
                    duration_seconds = ?, changed = ?
                WHERE id = ?
            ''', (status, message, file_path, file_size, duration, changed, job_id))
            conn.commit()
        except Exception as e:
            log.error(f"Failed to update job {job_id}: {e}")
        finally:
            conn.close()

    def cleanup_stale_jobs(self, max_age_minutes=30):
        """Mark old IN_PROGRESS jobs as UNKNOWN (crashed/interrupted)."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE jobs 
                SET status = 'UNKNOWN', message = 'Proceso terminado inesperadamente'
                WHERE status = 'IN_PROGRESS' 
                AND timestamp < datetime('now', ?)
            ''', (f'-{max_age_minutes} minutes',))
            affected = cursor.rowcount
            conn.commit()
            if affected > 0:
                log.warning(f"Marked {affected} stale IN_PROGRESS jobs as UNKNOWN")
            return affected
        except Exception as e:
            log.error(f"Failed to cleanup stale jobs: {e}")
            return 0
        finally:
            conn.close()

    def start_run(self, run_type="CRON", triggered_by=None, log_path=None):
        """Starts a batch run record with optional metadata."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO runs (start_time, type, triggered_by, log_path) 
                VALUES (?, ?, ?, ?)
            ''', (datetime.now(), run_type, triggered_by, log_path))
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            log.error(f"Failed to start run: {e}")
            return None
        finally:
            conn.close()

    def end_run(self, run_id, total, success, errors, log_path=None):
        """Updates the batch run record with final stats."""
        if not run_id:
            return
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            if log_path:
                cursor.execute('''
                    UPDATE runs 
                    SET end_time = ?, total_devices = ?, success_count = ?, error_count = ?, log_path = ?
                    WHERE id = ?
                ''', (datetime.now(), total, success, errors, log_path, run_id))
            else:
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

    def get_jobs(self, page=1, per_page=10, filters=None):
        """Get jobs with pagination and filters."""
        conn = self._get_connection()
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            query = "SELECT * FROM jobs WHERE 1=1"
            params = []
            
            if filters:
                if filters.get('status'):
                    query += " AND status = ?"
                    params.append(filters['status'])
                if filters.get('vendor'):
                    query += " AND vendor = ?"
                    params.append(filters['vendor'])
                if filters.get('search'):
                    query += " AND (hostname LIKE ? OR message LIKE ?)"
                    search_term = f"%{filters['search']}%"
                    params.extend([search_term, search_term])
                if filters.get('hostname_in') is not None:
                    # If list is empty but filter key exists, return no results
                    if not filters['hostname_in']:
                        query += " AND 1=0"
                    else:
                        placeholders = ','.join(['?'] * len(filters['hostname_in']))
                        query += f" AND hostname IN ({placeholders})"
                        params.extend(filters['hostname_in'])
            
            query += " ORDER BY id DESC LIMIT ? OFFSET ?"
            params.extend([per_page, (page - 1) * per_page])
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def get_jobs_count(self, filters=None):
        """Get total count of jobs matching filters."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            query = "SELECT count(*) FROM jobs WHERE 1=1"
            params = []
            
            if filters:
                if filters.get('status'):
                    query += " AND status = ?"
                    params.append(filters['status'])
                if filters.get('vendor'):
                    query += " AND vendor = ?"
                    params.append(filters['vendor'])
                if filters.get('search'):
                    query += " AND (hostname LIKE ? OR message LIKE ?)"
                    search_term = f"%{filters['search']}%"
                    params.extend([search_term, search_term])
                if filters.get('hostname_in') is not None:
                    if not filters['hostname_in']:
                        query += " AND 1=0"
                    else:
                        placeholders = ','.join(['?'] * len(filters['hostname_in']))
                        query += f" AND hostname IN ({placeholders})"
                        params.extend(filters['hostname_in'])

            cursor.execute(query, params)
            return cursor.fetchone()[0]
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

    def get_recent_jobs(self, limit=50):
        """Get recent jobs for dashboard display."""
        conn = self._get_connection()
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM jobs 
                ORDER BY id DESC 
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
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
    
    def update_device_model(self, model_id, name, vendor, description='', dev_type=''):
        """Update a device model."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('UPDATE device_models SET name = ?, vendor = ?, description = ?, type = ? WHERE id = ?',
                          (name, vendor, description, dev_type, model_id))
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

    def delete_old_jobs(self, days):
        """Delete jobs older than N days."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            limit_date = datetime.now() - timedelta(days=days)
            cursor.execute("DELETE FROM jobs WHERE timestamp < ?", (limit_date,))
            deleted = cursor.rowcount
            conn.commit()
            log.info(f"Deleted {deleted} old jobs from DB (older than {days} days)")
            return deleted
        except Exception as e:
            log.error(f"Failed to delete old jobs: {e}")
            return 0
        finally:
            conn.close()

    def get_last_job_status_all(self):
        """Get the last job status for each device.
        
        Returns dict: hostname -> {'status': 'SUCCESS'|'ERROR', 'changed': bool, 'timestamp': str}
        Used for showing backup status semaphore in historial view.
        """
        conn = self._get_connection()
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            # Get the most recent job for each hostname
            cursor.execute('''
                SELECT j.hostname, j.status, j.changed, j.timestamp, j.message
                FROM jobs j
                INNER JOIN (
                    SELECT hostname, MAX(id) as max_id
                    FROM jobs
                    GROUP BY hostname
                ) latest ON j.id = latest.max_id
            ''')
            result = {}
            for row in cursor.fetchall():
                result[row['hostname']] = {
                    'status': row['status'],
                    'changed': bool(row['changed']),
                    'timestamp': row['timestamp'],
                    'message': row['message']
                }
            return result
        except Exception as e:
            log.error(f"Failed to get last job status: {e}")
            return {}
        finally:
            conn.close()

    # ========================
    # AUDIT LOG
    # ========================
    
    def log_audit_event(self, user_id, username, event_type, event_category=None,
                        entity_type=None, entity_id=None, entity_name=None,
                        details=None, ip_address=None, user_agent=None):
        """Record an audit log entry."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            # Convert details dict to JSON string if provided
            details_str = None
            if details:
                import json
                details_str = json.dumps(details, ensure_ascii=False)
            
            cursor.execute('''
                INSERT INTO audit_log 
                (timestamp, user_id, username, event_type, event_category, 
                 entity_type, entity_id, entity_name, details, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (datetime.now(), user_id, username, event_type, event_category,
                  entity_type, entity_id, entity_name, details_str, ip_address, user_agent))
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            log.error(f"Failed to log audit event: {e}")
            return None
        finally:
            conn.close()
    
    def get_audit_logs(self, page=1, per_page=20, filters=None):
        """Get audit logs with pagination and filters."""
        conn = self._get_connection()
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            query = "SELECT * FROM audit_log WHERE 1=1"
            params = []
            
            if filters:
                if filters.get('event_type'):
                    query += " AND event_type = ?"
                    params.append(filters['event_type'])
                if filters.get('event_category'):
                    query += " AND event_category = ?"
                    params.append(filters['event_category'])
                if filters.get('user_id'):
                    query += " AND user_id = ?"
                    params.append(filters['user_id'])
                if filters.get('username'):
                    query += " AND username LIKE ?"
                    params.append(f"%{filters['username']}%")
                if filters.get('ip_address'):
                    query += " AND ip_address LIKE ?"
                    params.append(f"%{filters['ip_address']}%")
                if filters.get('date_from'):
                    query += " AND timestamp >= ?"
                    params.append(filters['date_from'])
                if filters.get('date_to'):
                    query += " AND timestamp <= ?"
                    params.append(filters['date_to'])
                if filters.get('entity_type'):
                    query += " AND entity_type = ?"
                    params.append(filters['entity_type'])
                if filters.get('search'):
                    query += " AND (entity_name LIKE ? OR details LIKE ?)"
                    search_term = f"%{filters['search']}%"
                    params.extend([search_term, search_term])
            
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([per_page, (page - 1) * per_page])
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            log.error(f"Failed to get audit logs: {e}")
            return []
        finally:
            conn.close()
    
    def get_audit_log_count(self, filters=None):
        """Get total count of audit logs matching filters."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            query = "SELECT count(*) FROM audit_log WHERE 1=1"
            params = []
            
            if filters:
                if filters.get('event_type'):
                    query += " AND event_type = ?"
                    params.append(filters['event_type'])
                if filters.get('event_category'):
                    query += " AND event_category = ?"
                    params.append(filters['event_category'])
                if filters.get('user_id'):
                    query += " AND user_id = ?"
                    params.append(filters['user_id'])
                if filters.get('username'):
                    query += " AND username LIKE ?"
                    params.append(f"%{filters['username']}%")
                if filters.get('ip_address'):
                    query += " AND ip_address LIKE ?"
                    params.append(f"%{filters['ip_address']}%")
                if filters.get('date_from'):
                    query += " AND timestamp >= ?"
                    params.append(filters['date_from'])
                if filters.get('date_to'):
                    query += " AND timestamp <= ?"
                    params.append(filters['date_to'])
                if filters.get('entity_type'):
                    query += " AND entity_type = ?"
                    params.append(filters['entity_type'])
                if filters.get('search'):
                    query += " AND (entity_name LIKE ? OR details LIKE ?)"
                    search_term = f"%{filters['search']}%"
                    params.extend([search_term, search_term])
            
            cursor.execute(query, params)
            return cursor.fetchone()[0]
        except Exception as e:
            log.error(f"Failed to get audit log count: {e}")
            return 0
        finally:
            conn.close()
    
    def get_audit_event_types(self):
        """Get list of distinct event types used in audit log."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT DISTINCT event_type FROM audit_log ORDER BY event_type')
            return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            log.error(f"Failed to get audit event types: {e}")
            return []
        finally:
            conn.close()
    
    def get_audit_users(self):
        """Get list of distinct users in audit log."""
        conn = self._get_connection()
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT DISTINCT user_id, username 
                FROM audit_log 
                WHERE user_id IS NOT NULL 
                ORDER BY username
            ''')
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            log.error(f"Failed to get audit users: {e}")
            return []
        finally:
            conn.close()
    
    def delete_old_audit_logs(self, days):
        """Delete audit logs older than N days."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            limit_date = datetime.now() - timedelta(days=days)
            cursor.execute("DELETE FROM audit_log WHERE timestamp < ?", (limit_date,))
            deleted = cursor.rowcount
            conn.commit()
            log.info(f"Deleted {deleted} old audit logs (older than {days} days)")
            return deleted
        except Exception as e:
            log.error(f"Failed to delete old audit logs: {e}")
            return 0
        finally:
            conn.close()
