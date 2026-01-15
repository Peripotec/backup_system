import time
import os
from vendors.base_vendor import BackupVendor
from settings import TFTP_ROOT
from core.logger import log
from core.vault import save_preferred_credential_for_device
from core.config_manager import get_config_manager


class Cisco(BackupVendor):
    """
    Cisco IOS backup via Telnet + TFTP.
    Supports Cisco routers and switches (7600, 6500, 3750, etc.)
    
    Uses 'copy running-config tftp://<server>/<filename>' command.
    """
    
    def backup(self):
        """
        Cisco backup process:
        1. Connect via Telnet
        2. Authenticate (try multiple credentials from pool)
        3. Send 'copy running-config tftp://<server>/<hostname>.conf'
        4. Confirm prompts
        5. Wait for file on TFTP server
        6. Process file for Git versioning
        """
        # Get TFTP server from DB config
        config = get_config_manager()
        tftp_server = config.get_setting('tftp_server') or '127.0.0.1'
        
        # Guardrail: Abort if TFTP server is localhost
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
            enable_pass = cred.get('extra_pass', password)  # Use extra_pass for enable, fallback to password
            cred_id = cred.get('id')
            
            self._debug_log(f"Probando credencial {i+1}/{len(credentials_to_try)}...")
            
            # Wait for login prompt
            if i == 0:
                self._debug_log("Esperando prompt de login...")
                self.read_until(tn, ["Username:", "username:", "login:"], timeout=15)
            else:
                self._debug_log("Esperando nuevo prompt de login...")
                self.read_until(tn, ["Username:", "username:"], timeout=10)
            
            time.sleep(0.3)
            self.send_command(tn, user, hide=False)
            
            self._debug_log("Enviando contraseña...")
            self.read_until(tn, ["Password:", "password:"])
            time.sleep(0.3)
            
            self.send_command(tn, password, hide=True)
            
            self._debug_log("Esperando respuesta...")
            # Cisco prompts: > (user mode), # (privileged mode), or failure
            idx, response = self.read_until(tn, [">", "#", "Username:", "% Login invalid"], timeout=15)
            
            # Check if login succeeded
            if idx in [0, 1]:  # Got > or #
                self._debug_log(f"✓ Login exitoso con credencial {i+1}")
                logged_in = True
                successful_cred_id = cred_id
                self.user = user
                self.password = password
                self.extra_pass = enable_pass
                
                # If we got > (user mode), need to enter enable mode
                if idx == 0:
                    self._debug_log("Entrando a modo privilegiado (enable)...")
                    self._enter_enable_mode(tn, enable_pass)
                
                break
            else:
                self._debug_log(f"✗ Credencial {i+1} falló")
                if i < len(credentials_to_try) - 1:
                    time.sleep(1)
        
        if not logged_in:
            tn.close()
            raise Exception(f"Authentication failed with all {len(credentials_to_try)} credentials")
        
        # Save successful credential
        if successful_cred_id:
            save_preferred_credential_for_device(self.hostname, successful_cred_id)
            self._debug_log(f"📝 Credencial guardada como preferida para {self.hostname}")
        
        # Execute backup command (usando formato del script original)
        # copy system:running-config tftp://<server>/<filename>
        config_filename = f"{self.hostname}.conf"
        cmd = f"copy system:running-config tftp://{tftp_server}/{config_filename}"
        
        self._debug_log(f"Ejecutando: {cmd}")
        self.send_command(tn, cmd)
        
        # El script original solo envía enters para confirmar prompts
        time.sleep(0.5)
        self.send_command(tn, "")  # Confirm address
        time.sleep(0.5)
        self.send_command(tn, "")  # Confirm filename
        
        # Wait for transfer to complete
        self._debug_log("Esperando fin de transferencia (max 60s)...")
        idx, response = self.read_until(tn, ["#", "bytes copied", "Error", "timed out"], timeout=60)
        
        if "error" in response.lower() or "timed out" in response.lower():
            tn.close()
            raise Exception(f"TFTP transfer failed: {response}")
        
        self._debug_log("✓ Transferencia completada")
        
        # Logout
        self._debug_log("Cerrando sesión...")
        self.send_command(tn, "exit")
        tn.close()
        
        # Verify file arrival
        file_path = os.path.join(TFTP_ROOT, config_filename)
        
        self._debug_log(f"Verificando archivo en {file_path}...")
        for i in range(10):
            if os.path.exists(file_path):
                self._debug_log(f"✓ Archivo encontrado")
                break
            self._debug_log(f"Esperando archivo... ({i+1}/10)")
            time.sleep(1)
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Backup file not found: {file_path}")
        
        # Process as TEXT for Git versioning (Cisco configs are plain text)
        self._debug_log("Procesando archivo para versionado...")
        return self.process_file(file_path, is_text=True)
    
    def _enter_enable_mode(self, tn, enable_pass):
        """
        Enter privileged EXEC mode (enable).
        """
        self.send_command(tn, "enable")
        
        idx, response = self.read_until(tn, ["Password:", "#"], timeout=10)
        
        if idx == 0:  # Password prompt
            self.send_command(tn, enable_pass, hide=True)
            idx, response = self.read_until(tn, ["#", ">", "% Access denied"], timeout=10)
            
            if "denied" in response.lower() or idx == 1:
                raise Exception("Enable password failed - access denied")
            
            self._debug_log("✓ Modo privilegiado activado")
        elif idx == 1:  # Already in # mode
            self._debug_log("✓ Ya en modo privilegiado")
