from vendors.base_vendor import BackupVendor
from settings import FTP_ROOT
from core.config_manager import get_config_manager
import time
import os

class ZteOlt(BackupVendor):
    def __init__(self, dev_info, db, git, credentials=None):
        super().__init__(dev_info, db, git, credentials)
        self.git_enabled = False # Binary files usually

    def backup(self):
        # Get TFTP/FTP server from DB config (single source of truth)
        config = get_config_manager()
        tftp_server = config.get_setting('tftp_server') or '127.0.0.1'
        
        # Guardrail: Abort if server is localhost
        if tftp_server in ('127.0.0.1', 'localhost', '::1'):
            raise ValueError(f"TFTP/FTP server is '{tftp_server}' - remote device cannot reach localhost. Configure correct IP in Settings.")
        
        self._debug_log(f"FTP Server: {tftp_server}")
        
        tn = self.connect_telnet()
        
        self.read_until(tn, ["Username:", "Login:"])
        tn.write(self.user.encode('ascii') + b"\n")
        
        self.read_until(tn, ["Password:"])
        tn.write(self.password.encode('ascii') + b"\n")
        
        self.read_until(tn, [">"])
        
        # Enable
        tn.write(b"enable\n")
        self.read_until(tn, ["Password:"])
        enable_pass = self.extra_pass if self.extra_pass else "zxr10"
        tn.write(enable_pass.encode('ascii') + b"\n")
        
        self.read_until(tn, ["#"])
        
        # Upload
        # file upload cfg-startup startrun.dat ftp ipaddress ...
        # Need FTP user/pass from settings or hardcoded?
        # Original: user ftpusuarios password noc442admin
        ftp_user = "ftpusuarios" # Should be in settings
        ftp_pass = "noc442admin"
        
        # Unique filename
        temp_filename = f"{self.hostname}.dat"
        
        cmd = f"file upload cfg-startup startrun.dat ftp ipaddress {tftp_server} user {ftp_user} password {ftp_pass} {temp_filename}\n"
        tn.write(cmd.encode('ascii'))
        
        # This can take a while
        self.read_until(tn, ["#"], timeout=120) 
        
        tn.write(b"exit\n")
        
        # Check FTP Root
        # Original script: /home/ftpusuarios/Contenedor-Backups/*.dat
        # We assume FTP_ROOT is /home/ftpusuarios
        expected_path = os.path.join(FTP_ROOT, temp_filename)
        
        # Verify
        for _ in range(5):
            if os.path.exists(expected_path):
                break
            time.sleep(1)
            
        return self.process_file(expected_path, is_text=False)

