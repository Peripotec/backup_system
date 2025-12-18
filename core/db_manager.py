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
