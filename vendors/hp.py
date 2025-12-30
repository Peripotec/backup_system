from vendors.base_vendor import BackupVendor
from settings import TFTP_ROOT
from core.config_manager import get_config_manager
import time
import os

class Hp(BackupVendor):
    def backup(self):
        # Get TFTP server from DB config (single source of truth)
        config = get_config_manager()
        tftp_server = config.get_setting('tftp_server') or '127.0.0.1'
        
        # Guardrail: Abort if TFTP server is localhost
        if tftp_server in ('127.0.0.1', 'localhost', '::1'):
            raise ValueError(f"TFTP server is '{tftp_server}' - remote device cannot reach localhost. Configure correct IP in Settings.")
        
        self._debug_log(f"TFTP Server: {tftp_server}")
        
        tn = self.connect_telnet()
        
        self.read_until(tn, ["name:", "Username:"])
        tn.write(self.user.encode('ascii') + b"\n")
        
        self.read_until(tn, ["Password:"])
        tn.write(self.password.encode('ascii') + b"\n")
        
        self.read_until(tn, [">", "]"])
        
        # HP Specific: _cmdline-mode on
        tn.write(b"_cmdline-mode on\n")
        self.read_until(tn, ["Y/N"])
        tn.write(b"Y\n")
        self.read_until(tn, ["word:"]) # Password for cmdline
        
        # Default HP CMDLine pass based on script
        # "Jinhua1920unauthorized" or "512900"
        # We need to handle this. It might be in 'extra_pass' or hardcoded logic?
        # Original script has hardcoded variants. 
        # Best practice: Put it in inventory credentials 'extra_pass'.
        
        cmd_pass = self.extra_pass if self.extra_pass else "512900" 
        tn.write(cmd_pass.encode('ascii') + b"\n")
        
        self.read_until(tn, [">", "]"])
        
        # Trigger TFTP
        # startup.cfg -> tftp
        temp_filename = f"{self.hostname}.cfg"
        cmd = f"tftp {tftp_server} put startup.cfg {temp_filename}\n"
        tn.write(cmd.encode('ascii'))
        
        self.read_until(tn, [">", "]"], timeout=60)
        tn.write(b"quit\n")
        
        expected_path = os.path.join(TFTP_ROOT, temp_filename)
        
        # Verify
        for _ in range(5):
            if os.path.exists(expected_path):
                break
            time.sleep(1)

        return self.process_file(expected_path, is_text=True)

