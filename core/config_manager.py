"""
Config Manager - Handles global settings and user management in SQLite.
"""
import sqlite3
import os
import secrets
import hashlib
import json
from datetime import datetime
from settings import DB_FILE
from core.logger import log

# Try to import bcrypt, fall back to hashlib if not available
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    log.warning("bcrypt not installed, using sha256 for password hashing (less secure)")


class ConfigManager:
    """Manages settings and users in SQLite."""
    
    def __init__(self, db_path=DB_FILE):
        self.db_path = db_path
        self._ensure_tables()
        self._ensure_defaults()
    
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _ensure_tables(self):
        """Create settings and users tables if they don't exist."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            
            # Settings table (key-value store)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT,
                    role TEXT DEFAULT 'viewer',
                    permissions TEXT DEFAULT '[]',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_login DATETIME,
                    active INTEGER DEFAULT 1
                )
            ''')
            
            # API Tokens table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS api_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    token TEXT UNIQUE NOT NULL,
                    name TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME,
                    last_used DATETIME,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # Migration: Add permissions column if it doesn't exist (for existing DBs)
            try:
                cursor.execute("SELECT permissions FROM users LIMIT 1")
            except sqlite3.OperationalError:
                log.info("Migrating database: adding permissions column to users table")
                cursor.execute("ALTER TABLE users ADD COLUMN permissions TEXT DEFAULT '[]'")
            
            conn.commit()
            log.debug("Config tables ensured")
        except Exception as e:
            log.error(f"Failed to create config tables: {e}")
            raise
        finally:
            conn.close()
    
    def _ensure_defaults(self):
        """Set default values for settings if not present."""
        defaults = {
            # Backup schedule
            'global_schedule': '02:00',
            'backup_enabled': 'true',
            
            # Retention
            'archive_retention_days': '90',
            'cleanup_enabled': 'true',
            
            # Email
            'smtp_host': '',
            'smtp_port': '587',
            'smtp_user': '',
            'smtp_pass': '',
            'email_recipients': '',
            'notify_on_error': 'true',
            'notify_on_success': 'false',
            
            # System
            'tftp_server': '127.0.0.1',
            'log_level': 'INFO',
        }
        
        for key, value in defaults.items():
            if self.get_setting(key) is None:
                self.set_setting(key, value)
        
        # Ensure default users exist (one per role for testing)
        default_users = [
            ('superadmin', 'super123', 'superadmin', 'superadmin@localhost'),
            ('admin', 'admin123', 'admin', 'admin@localhost'),
            ('operator', 'oper123', 'operator', 'operator@localhost'),
            ('viewer', 'viewer123', 'viewer', 'viewer@localhost'),
        ]
        for username, password, role, email in default_users:
            if not self.get_user(username):
                self.create_user(username, password, role, email)
                log.info(f"Default user created: {username} ({role})")
    
    # ==================
    # SETTINGS METHODS
    # ==================
    
    def get_setting(self, key):
        """Get a single setting value."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
            row = cursor.fetchone()
            return row['value'] if row else None
        finally:
            conn.close()
    
    def set_setting(self, key, value):
        """Set a setting value (insert or update)."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO settings (key, value, updated_at)
                VALUES (?, ?, ?)
            ''', (key, str(value), datetime.now()))
            conn.commit()
            return True
        except Exception as e:
            log.error(f"Failed to set setting {key}: {e}")
            return False
        finally:
            conn.close()
    
    def get_all_settings(self):
        """Get all settings as a dictionary."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT key, value FROM settings')
            return {row['key']: row['value'] for row in cursor.fetchall()}
        finally:
            conn.close()
    
    def update_settings(self, settings_dict):
        """Update multiple settings at once."""
        for key, value in settings_dict.items():
            self.set_setting(key, value)
        return True
    
    # ==================
    # USER METHODS
    # ==================
    
    def _hash_password(self, password):
        """Hash a password using bcrypt or sha256 fallback."""
        if BCRYPT_AVAILABLE:
            return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        else:
            # Fallback to sha256 with salt
            salt = secrets.token_hex(16)
            hash_obj = hashlib.sha256((salt + password).encode())
            return f"sha256:{salt}:{hash_obj.hexdigest()}"
    
    def _verify_password(self, password, password_hash):
        """Verify a password against its hash."""
        if BCRYPT_AVAILABLE and not password_hash.startswith('sha256:'):
            return bcrypt.checkpw(password.encode(), password_hash.encode())
        elif password_hash.startswith('sha256:'):
            _, salt, stored_hash = password_hash.split(':')
            hash_obj = hashlib.sha256((salt + password).encode())
            return hash_obj.hexdigest() == stored_hash
        return False
    
    def create_user(self, username, password, role='viewer', email=None, permissions=None):
        """Create a new user."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            password_hash = self._hash_password(password)
            # If no permissions specified, use role defaults
            if permissions is None:
                permissions = self._get_default_permissions(role)
            perms_json = json.dumps(permissions)
            cursor.execute('''
                INSERT INTO users (username, password_hash, email, role, permissions)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password_hash, email, role, perms_json))
            conn.commit()
            log.info(f"User created: {username} ({role})")
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            log.warning(f"User already exists: {username}")
            return None
        except Exception as e:
            log.error(f"Failed to create user {username}: {e}")
            return None
        finally:
            conn.close()
    
    def _get_default_permissions(self, role):
        """Get default permissions for a role."""
        defaults = {
            'viewer': ['view_dashboard', 'view_files', 'view_diff'],
            'operator': ['view_dashboard', 'view_files', 'view_diff', 'run_backup', 'view_inventory'],
            'admin': ['view_dashboard', 'view_files', 'view_diff', 'run_backup', 'view_inventory', 
                      'edit_inventory', 'view_vault', 'edit_vault', 'view_settings', 'edit_settings'],
            'superadmin': ['view_dashboard', 'view_files', 'view_diff', 'run_backup', 'view_inventory', 
                           'edit_inventory', 'view_vault', 'edit_vault', 'view_settings', 'edit_settings',
                           'manage_users'],
        }
        return defaults.get(role, ['view_dashboard', 'view_files', 'view_diff'])
    
    def get_user(self, username):
        """Get user by username."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()
    
    def get_user_by_id(self, user_id):
        """Get user by ID."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            row = cursor.fetchone()
            if row:
                user = dict(row)
                # Parse permissions JSON
                try:
                    user['permissions'] = json.loads(user.get('permissions') or '[]')
                except:
                    user['permissions'] = []
                return user
            return None
        finally:
            conn.close()
    
    def authenticate_user(self, username, password):
        """Authenticate user and return user dict if successful."""
        user = self.get_user(username)
        if user and user.get('active') and self._verify_password(password, user['password_hash']):
            # Update last login
            self._update_last_login(user['id'])
            return user
        return None
    
    def _update_last_login(self, user_id):
        """Update user's last login timestamp."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', 
                         (datetime.now(), user_id))
            conn.commit()
        finally:
            conn.close()
    
    def update_user(self, user_id, username=None, password=None, email=None, role=None, active=None, permissions=None):
        """Update user fields."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            updates = []
            values = []
            
            if username is not None:
                updates.append('username = ?')
                values.append(username)
            if password is not None:
                updates.append('password_hash = ?')
                values.append(self._hash_password(password))
            if email is not None:
                updates.append('email = ?')
                values.append(email)
            if role is not None:
                updates.append('role = ?')
                values.append(role)
            if active is not None:
                updates.append('active = ?')
                values.append(1 if active else 0)
            if permissions is not None:
                updates.append('permissions = ?')
                values.append(json.dumps(permissions))
            
            if updates:
                values.append(user_id)
                cursor.execute(f'UPDATE users SET {", ".join(updates)} WHERE id = ?', values)
                conn.commit()
                return True
            return False
        except Exception as e:
            log.error(f"Failed to update user {user_id}: {e}")
            return False
        finally:
            conn.close()
    
    def delete_user(self, user_id):
        """Delete a user."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()
    
    def get_all_users(self):
        """Get all users (without password hashes)."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT id, username, email, role, permissions, created_at, last_login, active FROM users')
            users = []
            for row in cursor.fetchall():
                user = dict(row)
                # Parse permissions JSON
                try:
                    user['permissions'] = json.loads(user.get('permissions') or '[]')
                except:
                    user['permissions'] = []
                users.append(user)
            return users
        finally:
            conn.close()
    
    # ==================
    # API TOKEN METHODS
    # ==================
    
    def create_api_token(self, user_id, name=None, expires_days=None):
        """Create a new API token for a user."""
        conn = self._get_connection()
        try:
            token = secrets.token_urlsafe(32)
            expires_at = None
            if expires_days:
                from datetime import timedelta
                expires_at = datetime.now() + timedelta(days=expires_days)
            
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO api_tokens (user_id, token, name, expires_at)
                VALUES (?, ?, ?, ?)
            ''', (user_id, token, name, expires_at))
            conn.commit()
            return token
        except Exception as e:
            log.error(f"Failed to create API token: {e}")
            return None
        finally:
            conn.close()
    
    def validate_api_token(self, token):
        """Validate an API token and return the associated user."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT t.*, u.username, u.role 
                FROM api_tokens t
                JOIN users u ON t.user_id = u.id
                WHERE t.token = ? AND u.active = 1
                AND (t.expires_at IS NULL OR t.expires_at > ?)
            ''', (token, datetime.now()))
            row = cursor.fetchone()
            if row:
                # Update last used
                cursor.execute('UPDATE api_tokens SET last_used = ? WHERE id = ?',
                             (datetime.now(), row['id']))
                conn.commit()
                return dict(row)
            return None
        finally:
            conn.close()
    
    def get_user_tokens(self, user_id):
        """Get all tokens for a user."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, name, created_at, expires_at, last_used
                FROM api_tokens WHERE user_id = ?
            ''', (user_id,))
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()
    
    def delete_api_token(self, token_id, user_id=None):
        """Delete an API token."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            if user_id:
                cursor.execute('DELETE FROM api_tokens WHERE id = ? AND user_id = ?', 
                             (token_id, user_id))
            else:
                cursor.execute('DELETE FROM api_tokens WHERE id = ?', (token_id,))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()


# Singleton instance
_config_manager = None

def get_config_manager():
    """Get or create the singleton ConfigManager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager
