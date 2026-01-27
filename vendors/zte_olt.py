import time
import os
import shutil
import threading
from vendors.base_vendor import BackupVendor
from settings import TFTP_ROOT
from core.logger import log
from core.vault import save_preferred_credential_for_device
from core.config_manager import get_config_manager

# Lock global para ZTE OLT backups - todos usan startrun.dat, deben ejecutar en secuencia
_zte_tftp_lock = threading.Lock()


class ZteOlt(BackupVendor):
    """
    ZTE OLT backup via Telnet + TFTP.
    
    Flujo:
    1. Login (Username/Password) → prompt >
    2. enable → Password (extra_pass) → prompt #
    3. file upload cfg-startup startrun.dat tftp ipaddress <server>
    4. exit
    5. Verificar startrun.dat y renombrar a hostname.dat
    """
    
    # Enable passwords conocidos para ZTE
    ENABLE_PASSWORDS = [
        "zxr10",  # Default ZTE enable password
    ]
    
    def backup(self):
        """Execute backup for ZTE OLT."""
        
        # Get TFTP server from DB config
        config = get_config_manager()
        tftp_server = config.get_setting('tftp_server') or '127.0.0.1'
        
        if tftp_server in ('127.0.0.1', 'localhost', '::1'):
            raise ValueError(f"TFTP server is '{tftp_server}' - remote device cannot reach localhost.")
        
        self._debug_log(f"TFTP Server: {tftp_server}")
        
        tn = self.connect_telnet()
        
        # =====================================================
        # FASE 1: Login
        # =====================================================
        logged_in = False
        successful_cred_id = None
        working_extra_pass = None
        
        credentials_to_try = self.credentials_pool if self.credentials_pool else [
            {"user": self.user, "pass": self.password, "extra_pass": self.extra_pass, "id": None}
        ]
        
        for i, cred in enumerate(credentials_to_try):
            user = cred.get('user', '')
            password = cred.get('pass', '')
            extra_pass = cred.get('extra_pass', '')
            cred_id = cred.get('id')
            
            self._debug_log(f"Probando credencial {i+1}/{len(credentials_to_try)}...")
            
            if i == 0:
                self._debug_log("Esperando prompt de login...")
                self.read_until(tn, ["sername:", "Username:", "login:"])
            else:
                self._debug_log("Esperando nuevo prompt de login...")
                self.read_until(tn, ["sername:", "Username:"], timeout=10)
            
            time.sleep(0.3)
            self.send_command(tn, user)
            
            self._debug_log("Enviando contraseña...")
            self.read_until(tn, ["assword:", "Password:"])
            time.sleep(0.3)
            
            try:
                tn.read_very_eager()
            except:
                pass
            
            self.send_command(tn, password, hide=True)
            
            self._debug_log("Esperando respuesta...")
            idx, response = self.read_until(tn, [">", "#", "sername:", "failed"], timeout=15)
            
            if idx in [0, 1] and "failed" not in response.lower():
                self._debug_log(f"✓ Login exitoso con credencial {i+1}")
                logged_in = True
                successful_cred_id = cred_id
                working_extra_pass = extra_pass
                self.user = user
                self.password = password
                break
            else:
                self._debug_log(f"✗ Credencial {i+1} falló")
                if i < len(credentials_to_try) - 1:
                    time.sleep(0.5)
                    if "sername:" not in response:
                        try:
                            self.read_until(tn, ["sername:", "Username:"], timeout=5)
                        except:
                            pass
        
        if not logged_in:
            tn.close()
            raise Exception(f"Authentication failed with all {len(credentials_to_try)} credentials")
        
        if successful_cred_id:
            save_preferred_credential_for_device(self.hostname, successful_cred_id)
            self._debug_log(f"📝 Credencial guardada como preferida para {self.hostname}")
        
        # =====================================================
        # FASE 2: Enable mode
        # =====================================================
        # Check if already in enable mode (#)
        current_prompt = response.strip()
        if "#" not in current_prompt:
            self._debug_log("Entrando en modo enable...")
            
            time.sleep(0.3)
            try:
                tn.read_very_eager()
            except:
                pass
            
            self.send_command(tn, "enable")
            idx, response = self.read_until(tn, ["assword:", "Password:", "#"], timeout=10)
            
            if idx in [0, 1]:  # Password prompt
                # Try enable passwords
                passwords_to_try = []
                if working_extra_pass:
                    passwords_to_try.append(working_extra_pass)
                passwords_to_try.extend(self.ENABLE_PASSWORDS)
                
                enable_success = False
                for enable_pass in passwords_to_try:
                    self._debug_log("Enviando enable password...")
                    self.send_command(tn, enable_pass, hide=True)
                    
                    idx2, response2 = self.read_until(tn, ["#", ">", "assword:"], timeout=10)
                    
                    if idx2 == 0:  # Got #
                        self._debug_log("✓ Enable mode activado")
                        enable_success = True
                        break
                    elif idx2 == 2:  # Password prompt again
                        self._debug_log("✗ Enable password incorrecto")
                        continue
                    else:
                        break
                
                if not enable_success:
                    self._debug_log("⚠ No se pudo entrar en enable mode")
                    tn.close()
                    raise Exception("Could not enter enable mode")
            elif idx == 2:
                self._debug_log("✓ Ya en enable mode")
        else:
            self._debug_log("✓ Ya en enable mode")
        
        # =====================================================
        # FASE 3: TFTP backup (con lock para evitar concurrencia)
        # =====================================================
        self._debug_log("Esperando lock TFTP...")
        with _zte_tftp_lock:
            self._debug_log("🔒 Lock TFTP adquirido")
            
            tftp_incoming = os.path.join(TFTP_ROOT, "startrun.dat")
            final_filename = f"{self.hostname}.dat"
            tftp_path = os.path.join(TFTP_ROOT, final_filename)
            
            # Prepare file for TFTP
            try:
                with open(tftp_incoming, 'w') as f:
                    pass
                os.chmod(tftp_incoming, 0o666)
                self._debug_log(f"✓ Archivo startrun.dat preparado para TFTP")
            except Exception as e:
                self._debug_log(f"⚠ No se pudo crear archivo TFTP: {e}")
            
            # Execute TFTP upload command
            # ZTE syntax: file upload cfg-startup startrun.dat tftp ipaddress <server>
            cmd = f"file upload cfg-startup startrun.dat tftp ipaddress {tftp_server}"
            self._debug_log(f"Ejecutando transferencia TFTP...")
            self.send_command(tn, cmd)
            
            # Wait for transfer to complete (ZTE can take a while)
            self._debug_log("Esperando fin de transferencia (max 120s)...")
            idx, response = self.read_until(tn, ["#", "success", "100%"], timeout=120)
            
            if "success" in response.lower() or "100%" in response:
                self._debug_log("✓ TFTP transfer completado")
            else:
                self._debug_log("⚠ Respuesta TFTP no confirmada")
            
            # =====================================================
            # FASE 4: Cerrar sesión
            # =====================================================
            self._debug_log("Cerrando sesión...")
            self.send_command(tn, "exit")
            try:
                tn.close()
            except:
                pass
            
            # =====================================================
            # FASE 5: Verificar archivo y renombrar
            # =====================================================
            self._debug_log(f"Verificando archivo en {tftp_incoming}...")
            
            for i in range(15):  # ZTE can be slow
                if os.path.exists(tftp_incoming) and os.path.getsize(tftp_incoming) > 0:
                    size = os.path.getsize(tftp_incoming)
                    self._debug_log(f"✓ Archivo encontrado ({size} bytes)")
                    
                    # Move to final location
                    shutil.move(tftp_incoming, tftp_path)
                    self._debug_log(f"✓ Renombrado a {final_filename}")
                    break
                self._debug_log(f"Esperando archivo... ({i+1}/15)")
                time.sleep(2)
            
            self._debug_log("🔓 Lock TFTP liberado")
        # FIN del lock
        
        if not os.path.exists(tftp_path) or os.path.getsize(tftp_path) == 0:
            raise FileNotFoundError(f"Backup file not found or empty: {tftp_path}")
        
        # =====================================================
        # FASE 6: Procesar para versionado
        # =====================================================
        self._debug_log("Procesando archivo para versionado...")
        return self.process_file(tftp_path, is_text=True)
