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
        self._debug_log("Esperando prompt de login...")
        self.read_until(tn, ["name:", "Username:"])
        time.sleep(0.3)  # Small delay to ensure buffer is clear
        self.send_command(tn, self.user, hide=False)
        
        self._debug_log("Enviando credenciales...")
        self.read_until(tn, ["Password:"])
        time.sleep(0.3)  # Small delay before sending password
        
        # Clear any leftover chars in buffer
        try:
            tn.read_very_eager()
        except:
            pass
        
        self.send_command(tn, self.password, hide=True)
        
        self._debug_log("Esperando prompt de sistema...")
        response = self.read_until(tn, [">", "]", "fail", "Fail", "Username:"], timeout=15)
        
        # Check if authentication failed
        if "fail" in response.lower() or "Username:" in response:
            self._debug_log("⚠ Primer intento falló, reintentando...")
            # Retry with same credentials (common Huawei quirk)
            time.sleep(0.5)
            self.send_command(tn, self.user, hide=False)
            self.read_until(tn, ["Password:"])
            time.sleep(0.3)
            self.send_command(tn, self.password, hide=True)
            self.read_until(tn, [">", "]"], timeout=15)
        
        # TFTP Upload with unique filename to avoid race conditions
        config_filename = "vrpcfg.zip"
        temp_filename = f"{self.hostname}.zip"
        
        # Command: tftp <server> put <local> <remote>
        cmd = f"tftp {SERVER_IP} put {config_filename} {temp_filename}"
        self._debug_log(f"Ejecutando transferencia TFTP...")
        self.send_command(tn, cmd)
        
        # Wait for transfer to complete
        self._debug_log("Esperando fin de transferencia (max 60s)...")
        self.read_until(tn, [">", "]"], timeout=60)
        
        self._debug_log("Cerrando sesión...")
        self.send_command(tn, "quit")
        tn.close()
        
        # Verify file arrival
        zip_path = os.path.join(TFTP_ROOT, temp_filename)
        
        self._debug_log(f"Verificando archivo en {zip_path}...")
        for i in range(10):
            if os.path.exists(zip_path):
                self._debug_log(f"✓ Archivo encontrado")
                break
            self._debug_log(f"Esperando archivo... ({i+1}/10)")
            time.sleep(1)
        
        if not os.path.exists(zip_path):
            raise FileNotFoundError(f"Backup file not found: {zip_path}")
        
        # Extract cfg from zip
        self._debug_log("Extrayendo configuración del ZIP...")
        cfg_content = self._extract_cfg_from_zip(zip_path)
        
        if cfg_content:
            # Save extracted cfg to temp file for processing
            temp_cfg = os.path.join(tempfile.gettempdir(), f"{self.hostname}.cfg")
            with open(temp_cfg, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(cfg_content)
            
            self._debug_log(f"✓ Extraído: {len(cfg_content)} bytes")
            
            # Clean up zip file
            os.remove(zip_path)
            
            # Process as TEXT for Git versioning
            self._debug_log("Procesando archivo para versionado...")
            return self.process_file(temp_cfg, is_text=True)
        else:
            # Fallback: process as binary if extraction fails
            self._debug_log("⚠ No se pudo extraer cfg, guardando como binario")
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
                self._debug_log(f"Archivos en ZIP: {names}")
                
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
            self._debug_log(f"✗ ZIP inválido: {zip_path}")
        except Exception as e:
            self._debug_log(f"✗ Error extrayendo: {e}")
        
        return None
