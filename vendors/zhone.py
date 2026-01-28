import time
import os
from vendors.base_vendor import BackupVendor
from settings import TFTP_ROOT
from core.logger import log
from core.vault import save_preferred_credential_for_device
from core.config_manager import get_config_manager


class Zhone(BackupVendor):
    """
    Zhone MXK backup via Telnet + TFTP.
    
    Uses 'dump network <ip_tftp> <filename>' command.
    """
    
    # Zhone transfers can be slow - use longer timeouts
    TIMEOUTS = {
        'connect': 10,
        'login': 20,
        'command': 30,
        'transfer': 180,  # Zhone needs more time for large configs
    }

    def send_command(self, tn, command, hide=False):
        """Override to send \r\n, required for some Zhone/MXK versions."""
        display = "****" if hide else command.strip()
        self._debug_log(f"→ {display}")
        tn.write(command.encode('ascii') + b"\r\n")

    
    def backup(self):
        """
        Zhone backup process:
        1. Connect via Telnet
        2. Authenticate
        3. Send 'dump network <server> <hostname>.cfg'
        4. Wait for completion (can take long time)
        5. Verify TFTP file
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
            {"user": self.user, "pass": self.password, "id": None}
        ]
        
        for i, cred in enumerate(credentials_to_try):
            user = cred.get('user', '')
            password = cred.get('pass', '')
            cred_id = cred.get('id')
            
            self._debug_log(f"Probando credencial {i+1}/{len(credentials_to_try)}...")
            
            # Wait for login prompt
            if i == 0:
                self._debug_log("Esperando prompt de login...")
                self.read_until(tn, ["ogin:", "Login:", "login:", "Username:"], timeout=15)
            else:
                self._debug_log("Esperando nuevo prompt de login...")
                self.read_until(tn, ["ogin:", "Login:", "login:", "Username:"], timeout=10)
            
            time.sleep(0.3)
            self.send_command(tn, user, hide=False)
            
            self._debug_log("Enviando contraseña...")
            self.read_until(tn, ["assword:", "Password:"])
            time.sleep(0.3)
            
            self.send_command(tn, password, hide=True)
            
            self._debug_log("Esperando respuesta...")
            # Zhone/MXK prompts
            # Success: "zSH>" or ">"
            # Failure: "Login incorrect", "bad password", or looped "login:" prompt
            idx, response = self.read_until(tn, ["zSH>", ">", "ogin:", "Login:", "incorrect", "bad password", "failed"], timeout=15)
            
            # Check if login succeeded
            # idx 0,1 = success
            # idx 2,3 = login prompt again (failure)
            # idx 4,5,6 = explicit failure message
            if idx in [0, 1] and "incorrect" not in response.lower() and "failed" not in response.lower():
                self._debug_log(f"✓ Login exitoso con credencial {i+1}")
                logged_in = True
                successful_cred_id = cred_id
                self.user = user
                self.password = password
                break
            else:
                self._debug_log(f"✗ Credencial {i+1} falló ({'Pass incorrecto' if idx >= 4 else 'No prompt'})")
                if i < len(credentials_to_try) - 1:
                    time.sleep(1)
        
        if not logged_in:
            tn.close()
            msg = f"Authentication failed with all {len(credentials_to_try)} credentials."
            if len(credentials_to_try) == 1:
                msg += " Hint: Assign more credentials to the Group in Inventory to enable auto-rotation."
            raise Exception(msg)
        
        # Save successful credential
        if successful_cred_id:
            save_preferred_credential_for_device(self.hostname, successful_cred_id)
            self._debug_log(f"📝 Credencial guardada como preferida para {self.hostname}")
        
        # Clear buffer before dumping
        try:
            tn.read_very_eager()
        except:
            pass
            
        # Execute backup command
        # Syntax: dump network <ip_tftp> <filename>
        config_filename = f"{self.hostname}.cfg"
        cmd = f"dump network {tftp_server} {config_filename}"
        
        self._debug_log(f"Ejecutando: {cmd}")
        self.send_command(tn, cmd)
        
        # Wait for transfer to complete - use configured timeout
        transfer_timeout = self.TIMEOUTS['transfer']
        self._debug_log(f"Esperando fin de transferencia (max {transfer_timeout}s)...")
        # We expect the prompt back "zSH>" when done
        idx, response = self.read_until(tn, ["zSH>", ">", "Error", "failed", "timeout"], timeout=transfer_timeout)
        
        if "error" in response.lower() or "failed" in response.lower() or "timeout" in response.lower():
            tn.close()
            raise Exception(f"TFTP transfer failed: {response}")
        
        self._debug_log("✓ Comando finalizado (prompt recuperado)")
        
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
        
        # Process as TEXT for Git versioning
        self._debug_log("Procesando archivo para versionado...")
        return self.process_file(file_path, is_text=True)
