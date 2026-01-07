import time
import os
from vendors.base_vendor import BackupVendor
from settings import TFTP_ROOT
from core.logger import log
from core.vault import save_preferred_credential_for_device
from core.config_manager import get_config_manager
import shutil


class Hp(BackupVendor):
    """
    HP/HPE/Aruba Switch backup via Telnet + TFTP.
    
    Flujo SIMPLE (sin cmdline-mode):
    1. Login (Username/Password) → queda en User View <hostname>
    2. tftp <server> put startup.cfg
    3. quit
    
    IMPORTANTE: NO entrar NUNCA en _cmdline-mode ni system-view.
    El comando tftp SOLO funciona en User View <hostname>.
    """
    
    def send_command(self, tn, command, hide=False):
        """Override para HP: usar \\r en lugar de \\n (como expect/bash)."""
        display = "****" if hide else command.strip()
        self._debug_log(f"→ {display}")
        tn.write(command.encode('ascii') + b"\r")
    
    def backup(self):
        """
        HP backup via Telnet + TFTP.
        Returns: (archive_path, file_size, changed_boolean)
        """
        # Get TFTP server from DB config
        config = get_config_manager()
        tftp_server = config.get_setting('tftp_server') or '127.0.0.1'
        
        if tftp_server in ('127.0.0.1', 'localhost', '::1'):
            raise ValueError(f"TFTP server is '{tftp_server}' - configure correct IP in Settings.")
        
        self._debug_log(f"TFTP Server: {tftp_server}")
        
        tn = self.connect_telnet()
        
        # =====================================================
        # FASE 1: Login
        # =====================================================
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
            
            if i == 0:
                self._debug_log("Esperando prompt de login...")
                self.read_until(tn, ["name:", "Username:"])
            else:
                self._debug_log("Esperando nuevo prompt de login...")
                self.read_until(tn, ["Username:"], timeout=10)
            
            time.sleep(0.3)
            self.send_command(tn, user)
            
            self._debug_log("Enviando contraseña...")
            self.read_until(tn, ["Password:"])
            time.sleep(0.3)
            
            try:
                tn.read_very_eager()
            except Exception:
                pass
            
            self.send_command(tn, password, hide=True)
            
            self._debug_log("Esperando respuesta...")
            idx, response = self.read_until(tn, [">", "Username:", "Invalid", "failed"], timeout=15)
            
            if idx == 0 and "invalid" not in response.lower() and "failed" not in response.lower():
                self._debug_log(f"✓ Login exitoso con credencial {i+1}")
                logged_in = True
                successful_cred_id = cred_id
                break
            else:
                self._debug_log(f"✗ Credencial {i+1} falló")
                if i < len(credentials_to_try) - 1:
                    time.sleep(0.5)
        
        if not logged_in:
            tn.close()
            raise Exception(f"Authentication failed with all {len(credentials_to_try)} credentials")
        
        if successful_cred_id:
            save_preferred_credential_for_device(self.hostname, successful_cred_id)
            self._debug_log(f"📝 Credencial guardada como preferida para {self.hostname}")
        
        # =====================================================
        # FASE 2: TFTP backup (directo, sin verificar modo)
        # =====================================================
        # Después del login estamos en User View <hostname>
        # Ejecutar tftp INMEDIATAMENTE sin hacer nada más
        
        tftp_incoming = os.path.join(TFTP_ROOT, "startup.cfg")
        final_filename = f"{self.hostname}.cfg"
        tftp_path = os.path.join(TFTP_ROOT, final_filename)
        
        # Preparar archivo TFTP
        try:
            with open(tftp_incoming, 'w') as f:
                pass
            os.chmod(tftp_incoming, 0o666)
            self._debug_log(f"✓ Archivo startup.cfg preparado")
        except Exception as e:
            self._debug_log(f"⚠ No se pudo crear archivo TFTP: {e}")
        
        # Ejecutar TFTP
        cmd = f"tftp {tftp_server} put startup.cfg"
        self._debug_log(f"Ejecutando: {cmd}")
        self.send_command(tn, cmd)
        
        # Esperar transferencia
        self._debug_log("Esperando fin de transferencia (max 60s)...")
        idx, response = self.read_until(tn, [">", "uploaded", "sent", "successfully"], timeout=60)
        
        if "uploaded" in response.lower() or "sent" in response.lower() or "successfully" in response.lower():
            self._debug_log("✓ TFTP completado")
        
        # =====================================================
        # FASE 3: Cerrar sesión
        # =====================================================
        self._debug_log("Cerrando sesión...")
        self.send_command(tn, "quit")
        try:
            tn.close()
        except Exception:
            pass
        
        # =====================================================
        # FASE 4: Verificar archivo
        # =====================================================
        self._debug_log(f"Verificando archivo...")
        
        for i in range(10):
            if os.path.exists(tftp_incoming) and os.path.getsize(tftp_incoming) > 0:
                size = os.path.getsize(tftp_incoming)
                self._debug_log(f"✓ Archivo encontrado ({size} bytes)")
                shutil.move(tftp_incoming, tftp_path)
                self._debug_log(f"✓ Renombrado a {final_filename}")
                break
            self._debug_log(f"Esperando archivo... ({i+1}/10)")
            time.sleep(1)
        
        if not os.path.exists(tftp_path) or os.path.getsize(tftp_path) == 0:
            raise FileNotFoundError(f"Backup file not found or empty: {tftp_path}")
        
        # =====================================================
        # FASE 5: Procesar para versionado
        # =====================================================
        self._debug_log("Procesando para versionado...")
        return self.process_file(tftp_path, is_text=True)
