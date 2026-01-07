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
    
    Flujo CORRECTO (confirmado por debug manual):
    1. Login (Username/Password) → prompt <hostname>
    2. _cmdline-mode on → Y → password → sigue en <hostname>
    3. tftp <server> put startup.cfg  ← REQUIERE cmdline-mode habilitado
    4. Verificar archivo TFTP
    
    IMPORTANTE:
    - El comando tftp NO funciona sin habilitar _cmdline-mode primero
    - HP usa \r (carriage return) como line ending
    """
    
    # Cmdline passwords conocidos para equipos HP
    CMDLINE_PASSWORDS = [
        "512900",                  # Más común en equipos nuevos
        "Jinhua1920",              # HP 1920 series
        "Jinhua1920unauthorized",  # Alternativo 1920
    ]
    
    def send_command(self, tn, command, hide=False):
        """Override para HP: usar \r en lugar de \n (como expect/bash)."""
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
        # FASE 1: Login con credential pool
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
                self.read_until(tn, ["name:", "Username:"])
            else:
                self._debug_log("Esperando nuevo prompt de login...")
                self.read_until(tn, ["Username:"], timeout=10)
            
            time.sleep(0.3)
            self.send_command(tn, user, hide=False)
            
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
                working_extra_pass = extra_pass
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
        # FASE 2: Habilitar _cmdline-mode (REQUERIDO para tftp)
        # =====================================================
        # Cuando falla el password, el switch vuelve al prompt normal
        # Por eso hay que re-ejecutar _cmdline-mode on para cada intento
        
        # Build password list: credential extra_pass first, then known passwords
        passwords_to_try = []
        if working_extra_pass:
            passwords_to_try.append(working_extra_pass)
        passwords_to_try.extend(self.CMDLINE_PASSWORDS)
        
        cmdline_success = False
        
        for i, cmdpass in enumerate(passwords_to_try):
            self._debug_log(f"Intento cmdline {i+1}/{len(passwords_to_try)}...")
            
            # Limpiar buffer
            time.sleep(0.3)
            try:
                tn.read_very_eager()
            except Exception:
                pass
            
            # 1. Enviar _cmdline-mode on
            self.send_command(tn, "_cmdline-mode on")
            idx, response = self.read_until(tn, ["Y/N]", ">"], timeout=10)
            
            if idx != 0:  # No got Y/N prompt
                self._debug_log("⚠ Cmdline mode no disponible")
                break
            
            # 2. Responder Y
            self.send_command(tn, "Y")
            self.read_until(tn, ["word:", "Password:"], timeout=10)
            
            # 3. Enviar password
            self.send_command(tn, cmdpass, hide=True)
            time.sleep(1)
            
            idx2, response2 = self.read_until(tn, [">", "word:", "Password:"], timeout=10)
            response_lower = response2.lower()
            
            if "invalid" in response_lower or "error" in response_lower:
                self._debug_log("✗ Password incorrecto")
                # El switch vuelve al prompt normal, continuar al siguiente intento
                # Esperar que vuelva al prompt
                if ">" not in response2:
                    self.read_until(tn, [">"], timeout=5)
                continue
            elif idx2 == 0:  # Got > prompt sin error
                # Verificar que realmente entró en cmdline mode
                if "warning" in response_lower or "developer" in response_lower:
                    self._debug_log("✓ Cmdline mode habilitado")
                    cmdline_success = True
                    break
                else:
                    # Puede que haya funcionado, verificar
                    self._debug_log("✓ Cmdline mode habilitado")
                    cmdline_success = True
                    break
            else:
                self._debug_log("✗ Respuesta inesperada")
                continue
        
        if not cmdline_success:
            self._debug_log("⚠ No se pudo habilitar cmdline mode con ningún password")
            tn.close()
            raise Exception("Could not enable cmdline mode - tftp requires it")
        
        # =====================================================
        # FASE 3: TFTP backup
        # =====================================================
        tftp_incoming = os.path.join(TFTP_ROOT, "startup.cfg")
        final_filename = f"{self.hostname}.cfg"
        tftp_path = os.path.join(TFTP_ROOT, final_filename)
        
        # Prepare file for TFTP
        try:
            with open(tftp_incoming, 'w') as f:
                pass
            os.chmod(tftp_incoming, 0o666)
            self._debug_log(f"✓ Archivo startup.cfg preparado para TFTP")
        except Exception as e:
            self._debug_log(f"⚠ No se pudo crear archivo TFTP: {e}")
        
        # Execute TFTP command
        cmd = f"tftp {tftp_server} put startup.cfg"
        self._debug_log(f"Ejecutando transferencia TFTP...")
        self.send_command(tn, cmd)
        
        # Wait for transfer
        self._debug_log("Esperando fin de transferencia (max 60s)...")
        idx, response = self.read_until(tn, [">", "uploaded", "sent"], timeout=60)
        
        if "uploaded" in response.lower() or "sent" in response.lower():
            self._debug_log("✓ TFTP transfer completado")
        
        # =====================================================
        # FASE 4: Cerrar sesión
        # =====================================================
        self._debug_log("Cerrando sesión...")
        self.send_command(tn, "quit")
        try:
            tn.close()
        except Exception:
            pass
        
        # =====================================================
        # FASE 5: Verificar archivo y renombrar
        # =====================================================
        self._debug_log(f"Verificando archivo en {tftp_incoming}...")
        
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
        # FASE 6: Sanitizar archivo para Git (UTF-8 clean)
        # =====================================================
        self._debug_log("Sanitizando archivo para Git...")
        try:
            # Leer con latin-1 (acepta cualquier byte)
            with open(tftp_path, 'r', encoding='latin-1') as f:
                content = f.read()
            
            # Reemplazar caracteres no-ASCII problemáticos
            # Mantener solo caracteres printables ASCII + newlines
            clean_content = ''
            for char in content:
                if ord(char) < 128 or char in 'áéíóúÁÉÍÓÚñÑüÜ':
                    clean_content += char
                elif ord(char) >= 128:
                    # Reemplazar caracteres problemáticos con ?
                    clean_content += '?'
            
            # Escribir como UTF-8
            with open(tftp_path, 'w', encoding='utf-8') as f:
                f.write(clean_content)
            
            self._debug_log("✓ Archivo sanitizado para Git")
        except Exception as e:
            self._debug_log(f"⚠ Error sanitizando: {e}")
        
        # =====================================================
        # FASE 7: Procesar para versionado
        # =====================================================
        self._debug_log("Procesando archivo para versionado...")
        return self.process_file(tftp_path, is_text=True)
