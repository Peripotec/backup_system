import time
import os
import zipfile
import tempfile
from vendors.base_vendor import BackupVendor
from settings import TFTP_ROOT, SERVER_IP
from core.logger import log

class Huawei(BackupVendor):
    def backup(self):
        """
        Huawei backup via Telnet + TFTP.
        Extracts vrpcfg.cfg from the zip for text versioning.
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
        zip_path = os.path.join(TFTP_ROOT, temp_filename)
        
        for _ in range(10):
            if os.path.exists(zip_path):
                break
            time.sleep(1)
        
        if not os.path.exists(zip_path):
            raise FileNotFoundError(f"Backup file not found: {zip_path}")
        
        # Extract cfg from zip
        cfg_content = self._extract_cfg_from_zip(zip_path)
        
        if cfg_content:
            # Save extracted cfg to temp file for processing
            temp_cfg = os.path.join(tempfile.gettempdir(), f"{self.hostname}.cfg")
            with open(temp_cfg, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(cfg_content)
            
            log.info(f"Extracted cfg from zip: {len(cfg_content)} bytes")
            
            # Clean up zip file
            os.remove(zip_path)
            
            # Process as TEXT for Git versioning
            return self.process_file(temp_cfg, is_text=True)
        else:
            # Fallback: process as binary if extraction fails
            log.warning(f"Could not extract cfg from zip, saving as binary")
            return self.process_file(zip_path, is_text=False)
    
    def _extract_cfg_from_zip(self, zip_path):
        """
        Extract vrpcfg.cfg (or similar) from the Huawei zip file.
        Returns the text content or None if extraction fails.
        """
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                # List files in zip
                names = zf.namelist()
                log.debug(f"Files in zip: {names}")
                
                # Look for cfg file (vrpcfg.cfg, startup.cfg, etc.)
                cfg_file = None
                for name in names:
                    if name.endswith('.cfg') or name.endswith('.txt'):
                        cfg_file = name
                        break
                
                if not cfg_file and names:
                    # Just use the first file
                    cfg_file = names[0]
                
                if cfg_file:
                    content = zf.read(cfg_file)
                    return content.decode('utf-8', errors='ignore')
                    
        except zipfile.BadZipFile:
            log.error(f"Invalid zip file: {zip_path}")
        except Exception as e:
            log.error(f"Error extracting zip: {e}")
        
        return None
