from vendors.base_vendor import BackupVendor
import os
import time

class Mikrotik(BackupVendor):
    """
    Mikrotik RouterOS backup via SSH.
    
    Uses '/export' command to get configuration text.
    Default SSH port: 91 (customized for this environment).
    """
    
    def __init__(self, device_info, db_manager, git_manager, credentials=None):
        super().__init__(device_info, db_manager, git_manager, credentials)
        # Override port: use device-specified port, or default to 91 for Mikrotik
        if self.port is None:
            self.port = 91
    
    def backup(self):
        """
        Connects via SSH and runs /export.
        """
        temp_path = f"temp_{self.hostname}.rsc"
        
        # Log immediately - this should appear in UI
        self._debug_log(f"[Mikrotik] Iniciando backup para {self.hostname}")
        self._debug_log(f"[Mikrotik] IP: {self.ip}, Puerto SSH: {self.port}")
        self._debug_log(f"[Mikrotik] Usuario: {self.user}")
        
        # 1. Connect SSH
        self._debug_log("[Mikrotik] Conectando vía SSH...")
        try:
            client = self.connect_ssh()
        except Exception as e:
            self._debug_log(f"[Mikrotik] ✗ Error de conexión: {e}")
            raise
        
        try:
            # 2. Run Export
            # /export verbose creates a very detailed config
            # simple /export is usually enough for restore
            command = "/export verbose"
            self._debug_log(f"Ejecutando comando: {command}")
            
            output = self.send_command_ssh(client, command)
            
            self._debug_log(f"Respuesta recibida: {len(output)} bytes")
            
            # 3. Validate Output
            # Mikrotik export normally starts with "# jan/02/1970..." or similar comments
            self._debug_log("Validando output...")
            if not output or len(output) < 50:
                raise ValueError(f"Recibido output sospechosamente corto: {len(output)} bytes")
            
            if "bad command" in output.lower() or "syntax error" in output.lower():
                 raise ValueError(f"Error en comando de backup: {output[:100]}...")

            self._debug_log("✓ Output válido")
            
            # 4. Save to Temp File
            self._debug_log(f"Guardando archivo temporal: {temp_path}")
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(output)
            
            self._debug_log(f"✓ Archivo guardado ({len(output)} bytes)")
            
            # 5. Process (Archive + Git)
            self._debug_log("Procesando archivo para versionado...")
            return self.process_file(temp_path, is_text=True)
            
        finally:
            client.close()
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass
