import time
import os
from vendors.base_vendor import BackupVendor
from settings import TFTP_ROOT, SERVER_IP

class Huawei(BackupVendor):
    def backup(self):
        """
        Huawei backup via Telnet + TFTP.
        Uses unique filename per device to avoid race conditions.
        """
        tn = self.connect_telnet()
        
        # Login
        self.read_until(tn, ["name:", "Username:"])
        tn.write(self.user.encode('ascii') + b"\n")
        
        self.read_until(tn, ["Password:"])
        tn.write(self.password.encode('ascii') + b"\n")
        
        self.read_until(tn, [">", "]"])
        
        # TFTP Upload with unique filename to avoid race conditions
        config_filename = "vrpcfg.zip"
        temp_filename = f"{self.hostname}.zip"
        
        # Command: tftp <server> put <local> <remote>
        cmd = f"tftp {SERVER_IP} put {config_filename} {temp_filename}\n"
        tn.write(cmd.encode('ascii'))
        
        # Wait for transfer to complete
        self.read_until(tn, [">", "]"], timeout=60)
        
        tn.write(b"quit\n")
        tn.close()
        
        # Verify file arrival
        expected_path = os.path.join(TFTP_ROOT, temp_filename)
        
        for _ in range(10):
            if os.path.exists(expected_path):
                break
            time.sleep(1)
        
        # Process file - treating .zip as binary for now
        # TODO: Add unzip logic for text diff support
        return self.process_file(expected_path, is_text=False)
