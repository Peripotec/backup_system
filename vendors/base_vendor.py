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
    
    Timeout Configuration:
        Override TIMEOUTS in subclass to customize per-phase timeouts.
        Example:
            class SlowVendor(BackupVendor):
                TIMEOUTS = {
                    'connect': 15,
                    'login': 30,
                    'command': 60,
                    'transfer': 300,
                }
    """
    
    # Default timeouts (seconds) - override in subclass if needed
    TIMEOUTS = {
        'connect': 10,    # Initial TCP connection
        'login': 15,      # Authentication phase
        'command': 30,    # Command execution
        'transfer': 120,  # File transfer (TFTP/FTP)
    }
    
    def __init__(self, device_info, db_manager, git_manager, credentials=None):
        self.hostname = device_info['hostname']
        self.ip = device_info['ip']
        self.port = device_info.get('port')  # None by default, let connection methods decide
        
        # Credentials from vault (list) or legacy inline
        if credentials and len(credentials) > 0:
            # Use first credential from vault as default; plugins can try others
            self.credentials_pool = credentials
            self.user = credentials[0].get('user', '')
            self.password = credentials[0].get('pass', '')
            self.extra_pass = credentials[0].get('extra_pass', '')
        else:
            # Legacy fallback: inline credentials in device_info
            creds = device_info.get('credentials', {})
            self.credentials_pool = []
            self.user = creds.get('user', '')
            self.password = creds.get('pass', '')
            self.extra_pass = creds.get('extra_pass', '')
        
        self.db = db_manager
        self.git = git_manager
        
        # Flags - override in subclass if needed
        self.git_enabled = True  # Default to True for text backups
        self.protocol = "telnet"  # Default
        
        # Debug logging callback - set by engine for real-time CLI output
        self.log_callback = None
    
    def _debug_log(self, message):
        """Send debug message to callback and standard log."""
        # Auto-prefix [hostname] if message doesn't already have context
        if not message.startswith('['):
            message = f"[{self.hostname}] {message}"
        # Use INFO level so messages appear in journalctl
        log.info(f"[VENDOR] {message}")
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

    def connect_telnet(self, timeout=None):
        """
        Basic Telnet connection helper.
        Returns a Telnet-compatible object.
        Uses TIMEOUTS['connect'] by default.
        """
        port = self.port or 23
        connect_timeout = timeout if timeout is not None else self.TIMEOUTS['connect']
        self._debug_log(f"Conectando a {self.ip}:{port} (Telnet, timeout={connect_timeout}s)...")
        try:
            tn = telnetlib_Telnet(self.ip, port, timeout=connect_timeout)
            self._debug_log(f"✓ Conexión establecida con {self.ip}")
            return tn
        except Exception as e:
            self._debug_log(f"✗ Error de conexión Telnet: {e}")
            raise ConnectionError(f"Telnet connection failed to {self.ip}: {e}")

    def connect_ssh(self, timeout=None):
        """
        SSH connection helper using paramiko.
        Returns a paramiko.SSHClient object.
        Uses TIMEOUTS['connect'] by default.
        """
        connect_timeout = timeout if timeout is not None else self.TIMEOUTS['connect']
        self._debug_log(f"Conectando a {self.ip}:{self.port or 22} (SSH, timeout={connect_timeout}s)...")
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # Use assigned credentials
            client.connect(
                self.ip, 
                port=self.port or 22, 
                username=self.user, 
                password=self.password,
                timeout=connect_timeout,
                allow_agent=False,
                look_for_keys=False
            )
            self._debug_log(f"✓ Conexión SSH establecida con {self.ip}")
            return client
        except ImportError:
            raise ImportError("Paramiko is required for SSH but not installed. Run 'pip install paramiko'")
        except Exception as e:
            self._debug_log(f"✗ Error de conexión SSH: {e}")
            raise ConnectionError(f"SSH connection failed to {self.ip}: {e}")

    def read_until(self, tn, expected_list, timeout=10):
        """Wrapper for read_until to handle multiple prompt possibilities (Telnet only)."""
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
        """Send a command (Telnet) and log it."""
        display = "****" if hide else command.strip()
        self._debug_log(f"→ {display}")
        tn.write(command.encode('ascii') + b"\n")

    def send_command_ssh(self, client, command, wait_time=1):
        """
        Send command via SSH and return output.
        Note: For simple commands, exec_command is easier than invoke_shell.
        """
        self._debug_log(f"→ (SSH) {command}")
        stdin, stdout, stderr = client.exec_command(command, timeout=30)
        output = stdout.read().decode('utf-8', errors='ignore')
        error = stderr.read().decode('utf-8', errors='ignore')
        
        if output:
            self._debug_log(f"← {output[:100]}..." if len(output) > 100 else f"← {output.strip()}")
        if error:
            self._debug_log(f"⚠️ Stderr: {error.strip()}")
            
        return output

