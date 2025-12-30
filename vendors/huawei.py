import time
import os
import zipfile
import tempfile
from vendors.base_vendor import BackupVendor
from settings import TFTP_ROOT
from core.logger import log
from core.vault import save_preferred_credential_for_device
from core.config_manager import get_config_manager

class Huawei(BackupVendor):
    def backup(self):
        """
        Huawei backup via Telnet + TFTP.
        Extracts vrpcfg.cfg from the zip for text versioning.
        """
        # Get TFTP server from DB config (single source of truth)
        config = get_config_manager()
        tftp_server = config.get_setting('tftp_server') or '127.0.0.1'
        
        # Guardrail: Abort if TFTP server is localhost (remote device can't reach it)
        if tftp_server in ('127.0.0.1', 'localhost', '::1'):
            raise ValueError(f"TFTP server is '{tftp_server}' - remote device cannot reach localhost. Configure correct IP in Settings.")
        
        self._debug_log(f"TFTP Server: {tftp_server}")
        
        tn = self.connect_telnet()
        
        # Try login with credential pool
        logged_in = False
        successful_cred_id = None
        credentials_to_try = self.credentials_pool if self.credentials_pool else [
            {"user": self.user, "pass": self.password, "extra_pass": self.extra_pass, "id": None}
        ]
        
        for i, cred in enumerate(credentials_to_try):
            user = cred.get('user', '')
            password = cred.get('pass', '')
            cred_id = cred.get('id')
            
            self._debug_log(f"Probando credencial {i+1}/{len(credentials_to_try)}...")
            
            # Wait for login prompt
            if i == 0:
                self._debug_log("Esperando prompt de login...")
                self.read_until(tn, ["name:", "Username:"])
            else:
                # For retry, wait for Username prompt
                self._debug_log("Esperando nuevo prompt de login...")
                self.read_until(tn, ["Username:"], timeout=10)
            
            time.sleep(0.3)
            self.send_command(tn, user, hide=False)
            
            self._debug_log("Enviando contraseña...")
            self.read_until(tn, ["Password:"])
            time.sleep(0.3)
            
            # Clear buffer
            try:
                tn.read_very_eager()
            except:
                pass
            
            self.send_command(tn, password, hide=True)
            
            self._debug_log("Esperando respuesta...")
            # Only check for > or ] as success, Username: as clear failure
            idx, response = self.read_until(tn, [">", "]", "Username:"], timeout=15)
            
            # Check if login succeeded (idx 0 or 1 means > or ])
            # Specific Huawei error pattern: "Error: Authentication fail"
            # Don't match on "Failed: X" which is just stats in banner
            auth_error = "error: authentication" in response.lower()
            
            if idx in [0, 1] and not auth_error:
                self._debug_log(f"✓ Login exitoso con credencial {i+1}")
                logged_in = True
                successful_cred_id = cred_id
                # Update current credentials for future use
                self.user = user
                self.password = password
                break
            else:
                self._debug_log(f"✗ Credencial {i+1} falló")
                if i < len(credentials_to_try) - 1:
                    time.sleep(0.5)
                    # Wait for Username prompt if not there
                    if "Username:" not in response:
                        try:
                            self.read_until(tn, ["Username:"], timeout=5)
                        except:
                            pass
        
        if not logged_in:
            tn.close()
            raise Exception(f"Authentication failed with all {len(credentials_to_try)} credentials")
        
        # Save successful credential to cache for next time
        if successful_cred_id:
            save_preferred_credential_for_device(self.hostname, successful_cred_id)
            self._debug_log(f"📝 Credencial guardada como preferida para {self.hostname}")
        
        # TFTP Upload with unique filename to avoid race conditions
        config_filename = "vrpcfg.zip"
        temp_filename = f"{self.hostname}.zip"
        
        # Command: tftp <server> put <local> <remote>
        cmd = f"tftp {tftp_server} put {config_filename} {temp_filename}"
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
