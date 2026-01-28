"""
Remote UI Notifier for scheduled_runner.
Sends backup status updates to the Flask web app via Unix socket or HTTP.
"""
import os

# Optional dependency for HTTP fallback
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.logger import log

# Production: Gunicorn runs on Unix socket, fallback to localhost for dev
# Can override with BACKUP_WEB_URL environment variable
UNIX_SOCKET_PATH = '/opt/backup_system/backup_manager.sock'
DEFAULT_WEB_URL = os.environ.get('BACKUP_WEB_URL', 'http://localhost/api/backup/remote-update')
REMOTE_UPDATE_SECRET = os.environ.get('BACKUP_REMOTE_SECRET', 'backup_system_2024')



class RemoteUINotifier:
    """
    Sends backup status updates to the Flask app for CRON backups.
    This allows scheduled backups to show progress in the web UI.
    """
    
    def __init__(self, run_time):
        self.run_time = run_time
        self.enabled = True
        self.success_count = 0
        self.error_count = 0
        self.use_socket = os.path.exists(UNIX_SOCKET_PATH)
        
        self._check_connection()
    
    def _check_connection(self):
        """Check if web app is reachable."""
        if self.use_socket:
            if os.path.exists(UNIX_SOCKET_PATH):
                log.debug(f"Using Unix socket: {UNIX_SOCKET_PATH}")
            else:
                log.warning("Unix socket not found - UI updates disabled")
                self.enabled = False
        else:
            # Fallback to HTTP
            if not HAS_REQUESTS:
                log.debug("requests library not available - UI notifications disabled")
                self.enabled = False
                return
            try:
                requests.post(DEFAULT_WEB_URL, json={}, timeout=2)
                log.debug("Web app reachable for remote updates (HTTP)")
            except Exception:
                log.warning("Web app not reachable via HTTP - UI updates disabled")
                self.enabled = False
    
    def _post(self, data):
        """Send POST request to web app via Unix socket or HTTP."""
        if not self.enabled:
            return
        
        try:
            import json as json_module
            body = json_module.dumps(data)
            
            if self.use_socket:
                self._post_socket(body)
            else:
                self._post_http(data)
        except Exception as e:
            log.debug(f"Remote UI update failed: {e}")
    
    def _post_socket(self, body):
        """Post via Unix socket."""
        import socket
        
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(UNIX_SOCKET_PATH)
        
        # Build HTTP request
        headers = [
            'POST /api/backup/remote-update HTTP/1.1',
            'Host: localhost',
            'Content-Type: application/json',
            f'Content-Length: {len(body)}',
            f'X-Backup-Secret: {REMOTE_UPDATE_SECRET}',
            'Connection: close',
            '',
            body
        ]
        
        request = '\r\n'.join(headers)
        sock.sendall(request.encode('utf-8'))
        
        # Read response (don't really care about it)
        try:
            sock.recv(1024)
        except:
            pass
        sock.close()
    
    def _post_http(self, data):
        """Post via HTTP (fallback)."""
        if HAS_REQUESTS:
            requests.post(
                DEFAULT_WEB_URL,
                json=data,
                headers={'X-Backup-Secret': REMOTE_UPDATE_SECRET},
                timeout=2
            )
    
    def notify_start(self, total_devices):
        """Notify that CRON backup is starting."""
        self._post({
            'action': 'start',
            'message': f'Backup automático ({self.run_time}) - {total_devices} dispositivos'
        })
    
    def notify_device_start(self, device_name):
        """Notify that a device backup is starting."""
        self._post({
            'action': 'update',
            'device': device_name,
            'status': 'start'
        })
    
    def notify_device_log(self, device_name, message):
        """Send debug log for a device."""
        self._post({
            'action': 'update',
            'device': device_name,
            'status': 'debug',
            'message': message
        })
    
    def notify_device_success(self, device_name, message):
        """Notify device backup success."""
        self.success_count += 1
        self._post({
            'action': 'update',
            'device': device_name,
            'status': 'success',
            'message': message
        })
    
    def notify_device_error(self, device_name, error_message):
        """Notify device backup error."""
        self.error_count += 1
        self._post({
            'action': 'update',
            'device': device_name,
            'status': 'error',
            'message': error_message
        })
    
    def notify_end(self):
        """Notify that CRON backup has finished."""
        self._post({
            'action': 'end',
            'success': self.success_count,
            'errors': self.error_count,
            'message': f'Completado: {self.success_count} OK, {self.error_count} errores'
        })


def create_remote_status_callback(notifier):
    """
    Create a callback function compatible with BackupEngine.status_callback.
    This bridges the engine's callback mechanism to the remote notifier.
    """
    def callback(device_name, status, message=None):
        if status == 'start':
            notifier.notify_device_start(device_name)
        elif status == 'success':
            notifier.notify_device_success(device_name, message or '')
        elif status == 'error':
            notifier.notify_device_error(device_name, message or '')
        elif status == 'debug':
            notifier.notify_device_log(device_name, message or '')
        # Other statuses (saving, git, etc) could be added if needed
    
    return callback
