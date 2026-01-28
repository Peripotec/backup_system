"""
Remote UI Notifier for scheduled_runner.
Sends backup status updates to the Flask web app via HTTP.
"""
import os
import requests
from core.logger import log

REMOTE_UPDATE_URL = os.environ.get('BACKUP_WEB_URL', 'http://localhost:5000') + '/api/backup/remote-update'
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
        self._check_connection()
    
    def _check_connection(self):
        """Check if web app is reachable."""
        try:
            # Just try to reach the endpoint - it will fail auth but we know it's there
            requests.post(REMOTE_UPDATE_URL, json={}, timeout=2)
            log.debug("Web app reachable for remote updates")
        except requests.exceptions.ConnectionError:
            log.warning("Web app not reachable - UI updates disabled for this run")
            self.enabled = False
        except Exception:
            pass  # Any response means server is up
    
    def _post(self, data):
        """Send POST request to web app."""
        if not self.enabled:
            return
        try:
            requests.post(
                REMOTE_UPDATE_URL,
                json=data,
                headers={'X-Backup-Secret': REMOTE_UPDATE_SECRET},
                timeout=2
            )
        except Exception as e:
            log.debug(f"Remote UI update failed: {e}")
    
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
