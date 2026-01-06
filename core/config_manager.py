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
            
            # Roles table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS roles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    emoji TEXT DEFAULT '👤',
                    description TEXT,
                    permissions TEXT DEFAULT '[]',
                    is_system INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
            
            # Email - Enterprise SMTP config
            'smtp_enabled': 'false',
            'smtp_host': '',
            'smtp_port': '25',
            'smtp_from': 'Backup System <backup@localhost>',
            'smtp_transport': 'plain',  # plain, starttls, ssl
            'smtp_auth': 'false',
            'smtp_user': '',
            'smtp_pass': '',
            'smtp_timeout': '15',
            'email_recipients': '',
            'notify_on_error': 'true',
            'notify_on_success': 'false',
            
            # System
            'tftp_server': '127.0.0.1',
            'log_level': 'INFO',
            
            # Inventory Source (NetBox integration)
            'inventory_source': 'yaml',  # yaml | netbox
            'netbox_url': '',             # e.g., https://netbox.example.com
            'netbox_token': '',           # API token
            'netbox_filter_tag': 'backup-enabled',  # Tag to filter devices
        }
        
        for key, value in defaults.items():
            if self.get_setting(key) is None:
                self.set_setting(key, value)
        
        # Ensure default system roles exist
        default_roles = [
            ('viewer', '👁️', 'Solo lectura - Ver dashboard, archivos y comparaciones', 
             ['view_dashboard', 'view_files', 'view_diff']),
            ('operator', '🔧', 'Operador - Ejecutar backups y ver inventario',
             ['view_dashboard', 'view_files', 'view_diff', 'run_backup', 'view_inventory']),
            ('admin', '⚙️', 'Administrador - Configurar sistema, vault e inventario',
             ['view_dashboard', 'view_files', 'view_diff', 'run_backup', 'view_inventory', 
              'edit_inventory', 'view_vault', 'edit_vault', 'view_settings', 'edit_settings']),
            ('superadmin', '🛡️', 'Super Administrador - Acceso total incluyendo gestión de usuarios',
             ['view_dashboard', 'view_files', 'view_diff', 'run_backup', 'view_inventory', 
              'edit_inventory', 'view_vault', 'edit_vault', 'view_settings', 'edit_settings',
              'manage_users', 'manage_roles']),
        ]
        for name, emoji, description, permissions in default_roles:
            if not self.get_role(name):
                self.create_role(name, emoji, description, permissions, is_system=True)
                log.info(f"Default role created: {name}")
        
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
    # SCHEDULING METHODS
    # ==================
    
    def parse_schedule(self, schedule_str):
        """
        Parse a schedule string (CSV of HH:MM times) into sorted list.
        Returns empty list if invalid.
        """
        if not schedule_str or not schedule_str.strip():
            return []
        
        times = []
        for part in schedule_str.split(','):
            part = part.strip()
            # Validate HH:MM format
            if len(part) == 5 and part[2] == ':':
                try:
                    h, m = int(part[:2]), int(part[3:])
                    if 0 <= h < 24 and 0 <= m < 60:
                        times.append(part)
                except ValueError:
                    continue
        
        # Deduplicate and sort
        return sorted(list(set(times)))
    
    def get_schedule_for_vendor(self, vendor):
        """Get schedule for a specific vendor."""
        key = f"schedule_vendor_{vendor.lower()}"
        return self.get_setting(key) or ''
    
    def set_schedule_for_vendor(self, vendor, schedule_str):
        """Set schedule for a specific vendor."""
        key = f"schedule_vendor_{vendor.lower()}"
        # Validate and normalize
        times = self.parse_schedule(schedule_str)
        self.set_setting(key, ', '.join(times))
        log.info(f"Schedule updated for vendor {vendor}: {times}")
    
    def get_schedule_for_model(self, vendor, model):
        """Get schedule for a specific vendor+model combination."""
        key = f"schedule_model_{vendor.lower()}_{model.lower().replace(' ', '_')}"
        return self.get_setting(key) or ''
    
    def set_schedule_for_model(self, vendor, model, schedule_str):
        """Set schedule for a specific vendor+model combination."""
        key = f"schedule_model_{vendor.lower()}_{model.lower().replace(' ', '_')}"
        times = self.parse_schedule(schedule_str)
        self.set_setting(key, ', '.join(times))
        log.info(f"Schedule updated for {vendor}/{model}: {times}")
    
    def get_effective_schedule(self, device):
        """
        Get effective schedule for a device using inheritance:
        device -> model -> vendor -> global
        
        Returns tuple: (list of HH:MM times, source)
        Source is one of: 'device', 'model', 'vendor', 'global'
        
        A device only matches ONE bucket (first match wins).
        Empty schedule = inherit from parent level (not "disable").
        """
        # 1. Check device-specific schedule (stored in inventory)
        device_schedule = device.get('schedule', '')
        if device_schedule:
            return self.parse_schedule(device_schedule), 'device'
        
        # 2. Check vendor+model schedule
        vendor = device.get('vendor', '')
        model = device.get('modelo', '')
        if vendor and model:
            model_schedule = self.get_schedule_for_model(vendor, model)
            if model_schedule:
                return self.parse_schedule(model_schedule), 'model'
        
        # 3. Check vendor schedule
        if vendor:
            vendor_schedule = self.get_schedule_for_vendor(vendor)
            if vendor_schedule:
                return self.parse_schedule(vendor_schedule), 'vendor'
        
        # 4. Fallback to global schedule
        global_schedule = self.get_setting('global_schedule') or ''
        return self.parse_schedule(global_schedule), 'global'

    
    def get_devices_for_current_time(self, devices, current_time_hhmm):
        """
        Given a list of devices and current time (HH:MM), return devices
        that should be backed up now based on their effective schedule.
        
        Tracks which "bucket" each device came from for debugging.
        A device only belongs to ONE bucket (first match wins in inheritance).
        """
        matching = []
        seen_ids = set()
        
        # Counters for logging
        buckets = {'device': 0, 'model': 0, 'vendor': 0, 'global': 0}
        
        for device in devices:
            device_id = device.get('sysname') or device.get('hostname')
            if device_id in seen_ids:
                continue
            
            schedule, source = self.get_effective_schedule(device)
            if current_time_hhmm in schedule:
                # Tag device with its schedule source for debugging
                device['_schedule_source'] = source
                matching.append(device)
                seen_ids.add(device_id)
                buckets[source] = buckets.get(source, 0) + 1
        
        # Log summary of what was selected and why
        if matching:
            summary_parts = []
            for src, count in buckets.items():
                if count > 0:
                    summary_parts.append(f"{count} por {src}")
            log.info(f"Tick {current_time_hhmm}: {len(matching)} devices ({', '.join(summary_parts)})")
        
        return matching
    
    def should_run_backup_now(self, current_time_hhmm):
        """
        Check if any backup should run at the current time.
        Used by the timer wrapper to early-exit if not needed.
        """
        # If backups are globally disabled, never run
        if self.get_setting('backup_enabled') != 'true':
            return False, "Backups deshabilitados globalmente"
        
        # Check if current time matches global schedule
        global_schedule = self.parse_schedule(self.get_setting('global_schedule') or '')
        if current_time_hhmm in global_schedule:
            return True, "Horario global"
        
        # Check all vendor schedules
        all_settings = self.get_all_settings()
        for key, value in all_settings.items():
            if key.startswith('schedule_vendor_') or key.startswith('schedule_model_'):
                times = self.parse_schedule(value)
                if current_time_hhmm in times:
                    return True, f"Horario específico: {key}"
        
        return False, "Fuera de horario programado"
    
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
    
    # ==================
    # ROLE METHODS
    # ==================
    
    def get_role(self, name):
        """Get role by name."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM roles WHERE name = ?', (name,))
            row = cursor.fetchone()
            if row:
                role = dict(row)
                try:
                    role['permissions'] = json.loads(role.get('permissions') or '[]')
                except:
                    role['permissions'] = []
                return role
            return None
        finally:
            conn.close()
    
    def get_role_by_id(self, role_id):
        """Get role by ID."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM roles WHERE id = ?', (role_id,))
            row = cursor.fetchone()
            if row:
                role = dict(row)
                try:
                    role['permissions'] = json.loads(role.get('permissions') or '[]')
                except:
                    role['permissions'] = []
                return role
            return None
        finally:
            conn.close()
    
    def get_all_roles(self):
        """Get all roles."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM roles ORDER BY id')
            roles = []
            for row in cursor.fetchall():
                role = dict(row)
                try:
                    role['permissions'] = json.loads(role.get('permissions') or '[]')
                except:
                    role['permissions'] = []
                roles.append(role)
            return roles
        finally:
            conn.close()
    
    def create_role(self, name, emoji='👤', description='', permissions=None, is_system=False):
        """Create a new role."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            perms_json = json.dumps(permissions or [])
            cursor.execute('''
                INSERT INTO roles (name, emoji, description, permissions, is_system)
                VALUES (?, ?, ?, ?, ?)
            ''', (name, emoji, description, perms_json, 1 if is_system else 0))
            conn.commit()
            log.info(f"Role created: {name}")
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            log.warning(f"Role already exists: {name}")
            return None
        except Exception as e:
            log.error(f"Failed to create role {name}: {e}")
            return None
        finally:
            conn.close()
    
    def update_role(self, role_id, name=None, emoji=None, description=None, permissions=None):
        """Update role fields."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            updates = []
            values = []
            
            if name is not None:
                updates.append('name = ?')
                values.append(name)
            if emoji is not None:
                updates.append('emoji = ?')
                values.append(emoji)
            if description is not None:
                updates.append('description = ?')
                values.append(description)
            if permissions is not None:
                updates.append('permissions = ?')
                values.append(json.dumps(permissions))
            
            if updates:
                values.append(role_id)
                cursor.execute(f'UPDATE roles SET {", ".join(updates)} WHERE id = ?', values)
                conn.commit()
                return True
            return False
        except Exception as e:
            log.error(f"Failed to update role {role_id}: {e}")
            return False
        finally:
            conn.close()
    
    def delete_role(self, role_id):
        """Delete a role (if not system and no users assigned)."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            
            # Check if role is system
            cursor.execute('SELECT is_system, name FROM roles WHERE id = ?', (role_id,))
            role = cursor.fetchone()
            if not role:
                return False, "Rol no encontrado"
            if role['is_system']:
                return False, "No se puede eliminar un rol del sistema"
            
            # Check if users are assigned to this role
            cursor.execute('SELECT COUNT(*) as count FROM users WHERE role = ?', (role['name'],))
            count = cursor.fetchone()['count']
            if count > 0:
                return False, f"No se puede eliminar: {count} usuario(s) tienen este rol"
            
            cursor.execute('DELETE FROM roles WHERE id = ?', (role_id,))
            conn.commit()
            log.info(f"Role deleted: {role['name']}")
            return True, "Rol eliminado"
        except Exception as e:
            log.error(f"Failed to delete role {role_id}: {e}")
            return False, str(e)
        finally:
            conn.close()
    
    def count_superadmins(self):
        """Count users with superadmin role."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM users WHERE role = 'superadmin' AND active = 1")
            return cursor.fetchone()['count']
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
