"""
Template de Plugin de Vendor para Backup System
================================================

INSTRUCCIONES:
1. Copie este archivo a vendors/ con el nombre de su vendor: vendors/mi_vendor.py
2. Renombre la clase de "VendorTemplate" a "MiVendor" (TitleCase, sin guiones bajos)
3. Implemente el método backup() según el protocolo del equipo
4. Pruebe con el script test_vendor.py incluido en docs/
5. Agregue los dispositivos al inventario

CONVENCIÓN DE NOMBRES:
- Archivo: vendors/fortigate.py
- Clase:   class Fortigate(BackupVendor)
- Inventory: vendor: fortigate

Para nombres compuestos:
- Archivo: vendors/palo_alto.py
- Clase:   class PaloAlto(BackupVendor)
- Inventory: vendor: palo_alto
"""

from vendors.base_vendor import BackupVendor
import os
import time


class VendorTemplate(BackupVendor):
    """
    [COMPLETAR] Descripción del vendor y método de backup.
    
    Protocolo: SSH / Telnet (elegir uno)
    Comando: [comando que obtiene la configuración]
    Puerto default: 22 (SSH) o 23 (Telnet)
    """
    
    def __init__(self, device_info, db_manager, git_manager, credentials=None):
        super().__init__(device_info, db_manager, git_manager, credentials)
        
        # OPCIONAL: Sobrescribir puerto default si este vendor usa uno diferente
        # if self.port is None:
        #     self.port = 8022  # Puerto customizado
    
    def backup(self):
        """
        Implementación del flujo de backup.
        
        DEBE retornar: (ruta_archivo, tamaño_bytes, hubo_cambios)
        
        Ejemplo de retorno:
            return self.process_file(temp_path, is_text=True)
        """
        vendor_name = self.__class__.__name__
        temp_path = f"temp_{self.hostname}.cfg"
        
        # === LOGGING (visible en consola web en tiempo real) ===
        self._debug_log(f"[{vendor_name}] Iniciando backup para {self.hostname}")
        self._debug_log(f"[{vendor_name}] IP: {self.ip}, Puerto: {self.port}")
        self._debug_log(f"[{vendor_name}] Usuario: {self.user}")
        
        # =========================================================
        # OPCIÓN A: Backup via SSH (recomendado para equipos modernos)
        # =========================================================
        try:
            self._debug_log(f"[{vendor_name}] Conectando vía SSH...")
            client = self.connect_ssh()
        except Exception as e:
            self._debug_log(f"[{vendor_name}] ✗ Error de conexión SSH: {e}")
            raise
        
        try:
            # [COMPLETAR] Comando para obtener configuración
            command = "show running-config"  # <-- AJUSTAR SEGÚN VENDOR
            self._debug_log(f"[{vendor_name}] Ejecutando: {command}")
            
            output = self.send_command_ssh(client, command)
            self._debug_log(f"[{vendor_name}] Respuesta: {len(output)} bytes")
            
            # Validar que el output tenga contenido válido
            if not output or len(output) < 50:
                raise ValueError(f"Output sospechosamente corto: {len(output)} bytes")
            
            # [OPCIONAL] Validar errores específicos del vendor
            if "error" in output.lower() or "invalid" in output.lower():
                raise ValueError(f"Error en comando: {output[:200]}...")
            
            self._debug_log(f"[{vendor_name}] ✓ Output válido")
            
            # Guardar a archivo temporal
            self._debug_log(f"[{vendor_name}] Guardando: {temp_path}")
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(output)
            
            # Procesar: mover a archive/ + commit en Git + retornar info
            # is_text=True  -> Configuración de texto (commit en Git)
            # is_text=False -> Archivo binario (solo archive, sin Git)
            self._debug_log(f"[{vendor_name}] Procesando para versionado...")
            return self.process_file(temp_path, is_text=True)
            
        finally:
            client.close()
            # Limpiar archivo temporal
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass
        
        # =========================================================
        # OPCIÓN B: Backup via Telnet (para equipos legacy)
        # =========================================================
        # Descomente esta sección si el equipo solo soporta Telnet
        #
        # try:
        #     self._debug_log(f"[{vendor_name}] Conectando vía Telnet...")
        #     tn = self.connect_telnet()
        # except Exception as e:
        #     self._debug_log(f"[{vendor_name}] ✗ Error de conexión Telnet: {e}")
        #     raise
        #
        # try:
        #     # Login (iterar credenciales si hay múltiples)
        #     self._login_telnet(tn)
        #     
        #     # Enviar comando
        #     command = "show running-config"
        #     self.send_command(tn, command)
        #     
        #     # Leer respuesta hasta prompt
        #     output = self.read_until(tn, [b"#", b">"], timeout=60)
        #     
        #     # [procesar output similar a SSH...]
        #     
        # finally:
        #     tn.close()
    
    def _login_telnet(self, tn):
        """
        Helper para autenticación Telnet.
        Itera sobre las credenciales disponibles.
        """
        for cred in self.credentials:
            try:
                self._debug_log(f"Intentando login con usuario: {cred.get('user')}")
                
                # Esperar prompt de usuario
                self.read_until(tn, [b"Username:", b"login:"], timeout=10)
                self.send_command(tn, cred.get('user', ''))
                
                # Esperar prompt de password
                self.read_until(tn, [b"Password:"], timeout=10)
                self.send_command(tn, cred.get('pass', ''))
                
                # Verificar login exitoso (esperar prompt del equipo)
                result = self.read_until(tn, [b"#", b">", b"denied"], timeout=10)
                
                if b"denied" not in result:
                    self.user = cred.get('user')
                    self.password = cred.get('pass')
                    self._debug_log(f"✓ Login exitoso")
                    return
                    
            except Exception as e:
                self._debug_log(f"✗ Login fallido: {e}")
                continue
        
        raise ValueError("No se pudo autenticar con ninguna credencial")


# =========================================================
# NOTAS ADICIONALES
# =========================================================
#
# MÉTODOS DISPONIBLES DE BackupVendor:
# - self.connect_ssh()             -> Cliente SSH conectado
# - self.send_command_ssh(c, cmd)  -> Ejecuta comando SSH
# - self.connect_telnet()          -> Conexión Telnet
# - self.send_command(tn, cmd)     -> Envía comando Telnet
# - self.read_until(tn, prompts)   -> Lee hasta prompt
# - self.process_file(path, is_text) -> ¡OBLIGATORIO! Procesa el backup
# - self._debug_log(msg)           -> Log visible en UI
#
# PROPIEDADES DISPONIBLES:
# - self.hostname  -> Nombre del equipo
# - self.ip        -> IP del equipo
# - self.port      -> Puerto de conexión
# - self.user      -> Usuario actual
# - self.password  -> Password actual
# - self.credentials -> Lista de credenciales
#
# REFERENCIAS:
# - SSH ejemplo real: vendors/mikrotik.py
# - Telnet ejemplo real: vendors/huawei.py, vendors/cisco.py
# - Backup binario: vendors/zte_olt.py
