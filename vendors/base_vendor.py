import os
import shutil
import time
import sys
from abc import ABC, abstractmethod
from datetime import datetime
from settings import ARCHIVE_DIR, LATEST_DIR, REPO_DIR
from settings import TFTP_ROOT, FTP_ROOT
from core.logger import log

# Handle telnetlib removal in Python 3.13+
if sys.version_info >= (3, 13):
    # Use telnetlib3 for Python 3.13+
    # Note: telnetlib3 is async, but we'll use a sync wrapper approach
    # For production, consider using pexpect or netmiko instead
    import socket
    
    class SimpleTelnet:
        """Simple synchronous telnet wrapper for Python 3.13+"""
        def __init__(self, host, port=23, timeout=10):
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(timeout)
            self.sock.connect((host, port))
            
        def write(self, data):
            self.sock.sendall(data)
            
        def read_until(self, expected, timeout=10):
            self.sock.settimeout(timeout)
            data = b""
            while expected not in data:
                try:
                    chunk = self.sock.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                except socket.timeout:
                    break
            return data
        
        def expect(self, patterns, timeout=10):
            """Match any of the pattern bytes in the received data."""
            self.sock.settimeout(timeout)
            data = b""
            while True:
                try:
                    chunk = self.sock.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    for i, pattern in enumerate(patterns):
                        if pattern in data:
                            return i, pattern, data
                except socket.timeout:
                    break
            return -1, None, data
            
        def close(self):
            self.sock.close()
    
    telnetlib_Telnet = SimpleTelnet
else:
    import telnetlib
    telnetlib_Telnet = telnetlib.Telnet


class BackupVendor(ABC):
    """
    Abstract Base Class for Vendor Plugins.
    Each vendor must implement the backup() method.
    """
    
    def __init__(self, device_info, db_manager, git_manager):
        self.hostname = device_info['hostname']
        self.ip = device_info['ip']
        self.port = device_info.get('port', 23)
        self.user = device_info['credentials']['user']
        self.password = device_info['credentials']['pass']
        self.extra_pass = device_info['credentials'].get('extra_pass')
        
        self.db = db_manager
        self.git = git_manager
        
        # Flags - override in subclass if needed
        self.git_enabled = True  # Default to True for text backups
        self.protocol = "telnet"  # Default
        
        # Debug logging callback - set by engine for real-time CLI output
        self.log_callback = None
    
    def _debug_log(self, message):
        """Send debug message to callback and standard log."""
        log.debug(message)
        if self.log_callback:
            self.log_callback(message)

    @abstractmethod
    def backup(self):
        """
        Main entry point. Must implement the specific logic:
        1. Connect
        2. Trigger Backup (push to TFTP/FTP)
        3. Verify file arrival
        4. Move and Version (using self.process_file)
        
        Returns: (archive_path, file_size, changed_boolean)
        """
        pass

    def process_file(self, temp_path, is_text=True):
        """
        Standard processing for a received backup file:
        - Moves to Archive
        - Updates Latest (Symlink or Copy)
        - Git Commit (if enabled/text)
        
        Returns: (archive_path, file_size, changed_boolean)
        """
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
        
        # 1. Define Paths
        vendor_name = self.__class__.__name__.lower()
        
        # Archive Path: /Backup/archive/<vendor>/<hostname>/<timestamp>.cfg
        archive_dir = os.path.join(ARCHIVE_DIR, vendor_name, self.hostname)
        os.makedirs(archive_dir, exist_ok=True)
        filename = f"{self.hostname}_{timestamp}.{'cfg' if is_text else 'dat'}"
        archive_path = os.path.join(archive_dir, filename)

        # Latest/Repo Path
        if self.git_enabled and is_text:
            repo_vendor_dir = os.path.join(REPO_DIR, vendor_name)
            os.makedirs(repo_vendor_dir, exist_ok=True)
            latest_path = os.path.join(repo_vendor_dir, f"{self.hostname}.cfg")
        else:
            latest_vendor_dir = os.path.join(LATEST_DIR, vendor_name)
            os.makedirs(latest_vendor_dir, exist_ok=True)
            ext = 'cfg' if is_text else 'dat'
            latest_path = os.path.join(latest_vendor_dir, f"{self.hostname}.{ext}")

        # 2. Validate File
        if not os.path.exists(temp_path):
            raise FileNotFoundError(f"Backup file not found: {temp_path}")
        
        file_size = os.path.getsize(temp_path)
        if file_size == 0:
            raise ValueError("Backup file is empty")

        # 3. Move/Copy Logic
        shutil.copy2(temp_path, archive_path)
        log.debug(f"Archived to {archive_path}")

        shutil.move(temp_path, latest_path)
        log.debug(f"Updated latest to {latest_path}")

        # 4. Versioning (Git)
        changed = False
        if self.git_enabled and is_text:
            changed = self.git.commit_file(latest_path, self.hostname, vendor_name)
        
        return archive_path, file_size, changed

    def connect_telnet(self):
        """
        Basic Telnet connection helper.
        Returns a Telnet-compatible object.
        """
        self._debug_log(f"Conectando a {self.ip}:{self.port}...")
        try:
            tn = telnetlib_Telnet(self.ip, self.port, timeout=10)
            self._debug_log(f"✓ Conexión establecida con {self.ip}")
            return tn
        except Exception as e:
            self._debug_log(f"✗ Error de conexión: {e}")
            raise ConnectionError(f"Telnet connection failed to {self.ip}: {e}")

    def read_until(self, tn, expected_list, timeout=10):
        """Wrapper for read_until to handle multiple prompt possibilities."""
        expected_bytes = [x.encode('ascii') for x in expected_list]
        index, match, text = tn.expect(expected_bytes, timeout)
        if isinstance(text, bytes):
            text = text.decode('ascii', errors='ignore')
        
        # Log the received output (truncate if too long)
        if text:
            preview = text.strip()[-200:] if len(text) > 200 else text.strip()
            if preview:
                self._debug_log(f"← {preview}")
        
        return index, text
    
    def send_command(self, tn, command, hide=False):
        """Send a command and log it."""
        display = "****" if hide else command.strip()
        self._debug_log(f"→ {display}")
        tn.write(command.encode('ascii') + b"\n")
