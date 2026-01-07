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
    
    Flujo (CORREGIDO):
    1. Login (Username/Password)
    2. tftp <server> put startup.cfg  ← En modo NORMAL (prompt <>)
    3. Verificar archivo TFTP
    
    NOTA IMPORTANTE:
    - El comando tftp SOLO funciona en modo normal (prompt <>)
    - NO funciona en cmdline-mode (prompt [])
    - Por eso ejecutamos tftp INMEDIATAMENTE después del login
    """
    
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
            except Exception:
                pass
            
            self.send_command(tn, password, hide=True)
            
            self._debug_log("Esperando respuesta...")
            idx, response = self.read_until(tn, [">", "]", "Username:", "Invalid"], timeout=15)
            
            # Check if login succeeded
            if idx in [0, 1] and "invalid" not in response.lower():
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
        
        # Save successful credential to cache for next time
        if successful_cred_id:
            save_preferred_credential_for_device(self.hostname, successful_cred_id)
            self._debug_log(f"📝 Credencial guardada como preferida para {self.hostname}")
        
        # =====================================================
        # FASE 2: TFTP backup (¡EN MODO NORMAL, NO CMDLINE!)
        # =====================================================
        # El comando tftp solo funciona cuando el prompt es <hostname>
        # NO funciona cuando está en cmdline-mode [hostname]
        
        # IMPORTANTE: Esperar a que el switch esté listo antes de enviar comandos
        # Primero limpiar buffer y esperar el prompt limpio
        self._debug_log("Esperando prompt del switch...")
        time.sleep(1)  # Dar tiempo al switch para mostrar el prompt
        
        # Limpiar cualquier basura en el buffer
        try:
            tn.read_very_eager()
        except Exception:
            pass
        
        # Enviar un Enter para forzar el prompt
        self.send_command(tn, "")
        idx, response = self.read_until(tn, [">"], timeout=5)
        self._debug_log(f"← Prompt recibido")
        
        tftp_incoming = os.path.join(TFTP_ROOT, "startup.cfg")
        final_filename = f"{self.hostname}.cfg"
        tftp_path = os.path.join(TFTP_ROOT, final_filename)
        
        # Create/clear startup.cfg for TFTP to write to
        try:
            with open(tftp_incoming, 'w') as f:
                pass
            os.chmod(tftp_incoming, 0o666)
            self._debug_log(f"✓ Archivo startup.cfg preparado para TFTP")
        except Exception as e:
            self._debug_log(f"⚠ No se pudo crear archivo TFTP: {e}")
        
        # HP TFTP command - SIN nombre destino (llega como startup.cfg)
        cmd = f"tftp {tftp_server} put startup.cfg"
        self._debug_log(f"Ejecutando transferencia TFTP...")
        self.send_command(tn, cmd)
        
        # Wait for transfer to complete
        self._debug_log("Esperando fin de transferencia (max 60s)...")
        idx, response = self.read_until(tn, [">", "uploaded", "sent"], timeout=60)
        
        # Check for success indicators
        if "uploaded" in response.lower() or "sent" in response.lower():
            self._debug_log("✓ TFTP transfer completado")
        
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
        # FASE 4: Verificar archivo y renombrar
        # =====================================================
        self._debug_log(f"Verificando archivo en {tftp_incoming}...")
        
        for i in range(10):
            if os.path.exists(tftp_incoming) and os.path.getsize(tftp_incoming) > 0:
                size = os.path.getsize(tftp_incoming)
                self._debug_log(f"✓ Archivo encontrado ({size} bytes)")
                # Rename to final filename
                shutil.move(tftp_incoming, tftp_path)
                self._debug_log(f"✓ Renombrado a {final_filename}")
                break
            self._debug_log(f"Esperando archivo... ({i+1}/10)")
            time.sleep(1)
        
        if not os.path.exists(tftp_path) or os.path.getsize(tftp_path) == 0:
            raise FileNotFoundError(f"Backup file not found or empty: {tftp_path}")
        
        # =====================================================
        # FASE 5: Procesar archivo para versionado
        # =====================================================
        self._debug_log("Procesando archivo para versionado...")
        return self.process_file(tftp_path, is_text=True)
