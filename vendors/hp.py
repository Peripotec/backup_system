import time
import os
from vendors.base_vendor import BackupVendor
from settings import TFTP_ROOT
from core.logger import log
from core.vault import save_preferred_credential_for_device
from core.config_manager import get_config_manager


class Hp(BackupVendor):
    """
    HP/HPE/Aruba Switch backup via Telnet + TFTP.
    
    Flujo:
    1. Login (Username/Password)
    2. _cmdline-mode on → Y
    3. Password de cmdline (prueba múltiples: 512900, Jinhua1920unauthorized)
    4. tftp <server> put startup.cfg
    5. Archivo llega como texto (.cfg)
    """
    
    # Cmdline passwords conocidos para equipos HP
    # Se prueban en orden hasta que uno funcione
    CMDLINE_PASSWORDS = [
        "512900",                  # Más común en equipos nuevos
        "Jinhua1920unauthorized",  # Algunos modelos 1920
    ]
    
    def backup(self):
        """
        HP backup via Telnet + TFTP.
        Returns: (archive_path, file_size, changed_boolean)
        """
        # Get TFTP server from DB config (single source of truth)
        config = get_config_manager()
        tftp_server = config.get_setting('tftp_server') or '127.0.0.1'
        
        # Guardrail: Abort if TFTP server is localhost
        if tftp_server in ('127.0.0.1', 'localhost', '::1'):
            raise ValueError(f"TFTP server is '{tftp_server}' - remote device cannot reach localhost. Configure correct IP in Settings.")
        
        self._debug_log(f"TFTP Server: {tftp_server}")
        
        tn = self.connect_telnet()
        
        # =====================================================
        # FASE 1: Login con credential pool
        # =====================================================
        logged_in = False
        successful_cred_id = None
        credentials_to_try = self.credentials_pool if self.credentials_pool else [
            {"user": self.user, "pass": self.password, "extra_pass": self.extra_pass, "id": None}
        ]
        
        for i, cred in enumerate(credentials_to_try):
            user = cred.get('user', '')
            password = cred.get('pass', '')
            extra_pass = cred.get('extra_pass', '')
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
            idx, response = self.read_until(tn, [">", "]", "Username:", "Invalid"], timeout=15)
            
            # Check if login succeeded
            if idx in [0, 1] and "invalid" not in response.lower():
                self._debug_log(f"✓ Login exitoso con credencial {i+1}")
                logged_in = True
                successful_cred_id = cred_id
                # Store extra_pass for cmdline mode
                self.extra_pass = extra_pass
                self.user = user
                self.password = password
                break
            else:
                self._debug_log(f"✗ Credencial {i+1} falló")
                if i < len(credentials_to_try) - 1:
                    time.sleep(0.5)
        
        if not logged_in:
            tn.close()
            raise Exception(f"Authentication failed with all {len(credentials_to_try)} credentials")
        
        # Save successful credential to cache for next time
        if successful_cred_id:
            save_preferred_credential_for_device(self.hostname, successful_cred_id)
            self._debug_log(f"📝 Credencial guardada como preferida para {self.hostname}")
        
        # =====================================================
        # FASE 2: _cmdline-mode on (HP/Aruba specific)
        # =====================================================
        self._debug_log("Habilitando _cmdline-mode...")
        self.send_command(tn, "_cmdline-mode on")
        
        idx, response = self.read_until(tn, ["Y/N]", ">"], timeout=10)
        
        if idx == 0:  # Got Y/N prompt
            self.send_command(tn, "Y")
            self.read_until(tn, ["word:", "Password:"], timeout=10)
            
            # Try cmdline passwords
            cmdline_success = False
            
            # First try extra_pass from credential if provided
            passwords_to_try = []
            if self.extra_pass:
                passwords_to_try.append(self.extra_pass)
            passwords_to_try.extend(self.CMDLINE_PASSWORDS)
            
            for idx_p, cmdpass in enumerate(passwords_to_try):
                self._debug_log(f"Probando cmdline password {idx_p+1}/{len(passwords_to_try)}...")
                self.send_command(tn, cmdpass, hide=True)
                
                # Wait for response - need to distinguish between success and failure
                idx2, response2 = self.read_until(tn, [">", "Invalid", "Error", "word:"], timeout=10)
                
                if idx2 == 0:  # Got ">" prompt = success
                    self._debug_log("✓ Cmdline mode habilitado")
                    cmdline_success = True
                    break
                elif idx2 == 3:  # Got "word:" = wrong password, try again
                    self._debug_log("✗ Cmdline password falló, reintentando...")
                    continue
                else:
                    # Error case
                    self._debug_log(f"✗ Cmdline password falló: {response2[:50] if response2 else 'unknown'}")
                    # Wait a bit and check for new prompt
                    time.sleep(0.5)
                    continue
            
            if not cmdline_success:
                self._debug_log("⚠ No se pudo habilitar cmdline mode, continuando sin él...")
                # Some HP devices work without cmdline mode
        else:
            self._debug_log("Cmdline mode no requerido o ya activo")
        
        # Small delay to ensure clean state
        time.sleep(0.3)
        
        # =====================================================
        # FASE 3: TFTP backup
        # =====================================================
        temp_filename = f"{self.hostname}.cfg"
        
        # Create empty file for TFTP to write to
        tftp_path = os.path.join(TFTP_ROOT, temp_filename)
        try:
            # Touch file
            with open(tftp_path, 'w') as f:
                pass
            os.chmod(tftp_path, 0o666)
        except Exception as e:
            self._debug_log(f"⚠ No se pudo crear archivo TFTP: {e}")
        
        # Comando TFTP según bash original: tftp <server> put startup.cfg
        # El archivo se renombra después en el servidor TFTP
        cmd = f"tftp {tftp_server} put startup.cfg {temp_filename}"
        self._debug_log(f"Ejecutando: {cmd}")
        self.send_command(tn, cmd)
        
        # Wait for transfer to complete
        self._debug_log("Esperando fin de transferencia (max 60s)...")
        self.read_until(tn, [">", "]"], timeout=60)
        
        self._debug_log("Cerrando sesión...")
        self.send_command(tn, "quit")
        tn.close()
        
        # =====================================================
        # FASE 4: Verificar archivo y procesar
        # =====================================================
        self._debug_log(f"Verificando archivo en {tftp_path}...")
        
        for i in range(10):
            if os.path.exists(tftp_path) and os.path.getsize(tftp_path) > 0:
                self._debug_log(f"✓ Archivo encontrado ({os.path.getsize(tftp_path)} bytes)")
                break
            self._debug_log(f"Esperando archivo... ({i+1}/10)")
            time.sleep(1)
        
        if not os.path.exists(tftp_path) or os.path.getsize(tftp_path) == 0:
            raise FileNotFoundError(f"Backup file not found or empty: {tftp_path}")
        
        # Process as TEXT for Git versioning
        self._debug_log("Procesando archivo para versionado...")
        return self.process_file(tftp_path, is_text=True)
