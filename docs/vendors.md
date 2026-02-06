# Vendors y Plugins

El sistema utiliza una arquitectura **plug-and-play** para soportar múltiples fabricantes. Agregar un nuevo vendor es tan simple como crear un archivo `.py` en la carpeta `vendors/` y reiniciar el servicio.

> [!TIP]
> **A partir de la versión actual**, el sistema detecta automáticamente los plugins de vendors al iniciar. No es necesario editar ningún mapping, API, o código adicional.

---

## 🏗️ Arquitectura Plug-and-Play

```
📁 vendors/
   └── nuevo_vendor.py     ← Solo crear este archivo
       └── class NuevoVendor(BackupVendor)
           └── def backup(self): ...

✅ El sistema automáticamente:
   - Carga el plugin dinámicamente
   - Crea las carpetas de almacenamiento
   - Genera el mapping para APIs y frontend
   - Habilita historial Git y diff viewer
```

### Convenciones de Nombres (Obligatorias)

| Elemento | Formato | Ejemplo |
|----------|---------|---------|
| Archivo | `snake_case.py` | `mikrotik.py`, `zte_olt.py` |
| Clase | `TitleCase` (sin guiones bajos) | `Mikrotik`, `ZteOlt` |
| Inventario | `snake_case` (igual al archivo sin .py) | `vendor: mikrotik` |
| Carpeta backup | `lowercase` (nombre de clase) | `/archive/mikrotik/` |

### Ejemplos de Conversión Automática

| Archivo Plugin | Clase Esperada | Carpeta Creada | Inventario |
|----------------|----------------|----------------|------------|
| `mikrotik.py` | `Mikrotik` | `mikrotik/` | `vendor: mikrotik` |
| `zte_olt.py` | `ZteOlt` | `zteolt/` | `vendor: zte_olt` |
| `fortigate.py` | `Fortigate` | `fortigate/` | `vendor: fortigate` |
| `palo_alto.py` | `PaloAlto` | `paloalto/` | `vendor: palo_alto` |

---

## 📋 Vendors Soportados Actualmente

| Vendor | Archivo | Protocolo | Método |
|--------|---------|-----------|--------|
| **Huawei** | `huawei.py` | Telnet | `tftp put` (zip) |
| **Cisco** | `cisco.py` | Telnet | `copy running-config tftp` |
| **HP** | `hp.py` | Telnet | `copy startup-config tftp` |
| **ZTE OLT** | `zte_olt.py` | Telnet | `file upload ... tftp` |
| **ASGA** | `asga.py` | Telnet | `copy running-config tftp` |
| **Zhone** | `zhone.py` | Telnet | `dump network ...` |
| **MikroTik** | `mikrotik.py` | SSH | `/export verbose` |

---

## 🛠️ Guía Completa: Agregar Nuevo Vendor

### Paso 1: Elegir Nombre del Plugin

El nombre del archivo determina todo lo demás:

```
vendors/fortigate.py  →  class Fortigate  →  carpeta /fortigate/  →  vendor: fortigate
```

> [!WARNING]
> **Para nombres compuestos**, use guión bajo en el archivo pero elimínelos en la clase:
> - Archivo: `palo_alto.py`
> - Clase: `PaloAlto` (NO `Palo_Alto`)
> - Inventario: `vendor: palo_alto`

### Paso 2: Crear el Plugin

Use esta plantilla como base. Es un ejemplo funcional basado en el plugin de MikroTik:

```python
"""
Plugin de backup para [NOMBRE DEL VENDOR]
Protocolo: SSH / Telnet (elegir uno)
"""

from vendors.base_vendor import BackupVendor
import os
import time

class NuevoVendor(BackupVendor):
    """
    [Descripción breve del vendor y método de backup]
    
    Protocolo: SSH (o Telnet)
    Comando: [comando que obtiene la configuración]
    Puerto default: [22/23/etc]
    """
    
    def __init__(self, device_info, db_manager, git_manager, credentials=None):
        super().__init__(device_info, db_manager, git_manager, credentials)
        # OPCIONAL: Sobrescribir puerto default si es diferente a 22/23
        # if self.port is None:
        #     self.port = 8022  # Puerto custom
    
    def backup(self):
        """
        Implementación del flujo de backup.
        DEBE devolver: (ruta_archivo, tamaño, hubo_cambios)
        """
        temp_path = f"temp_{self.hostname}.cfg"
        
        # === LOGGING (aparece en consola web en tiempo real) ===
        self._debug_log(f"[{self.__class__.__name__}] Iniciando backup para {self.hostname}")
        self._debug_log(f"IP: {self.ip}, Puerto: {self.port}")
        self._debug_log(f"Usuario: {self.user}")
        
        # === OPCIÓN A: SSH ===
        try:
            self._debug_log("Conectando vía SSH...")
            client = self.connect_ssh()
        except Exception as e:
            self._debug_log(f"✗ Error de conexión: {e}")
            raise
        
        try:
            # Ejecutar comando de backup
            command = "show running-config"  # Ajustar según vendor
            self._debug_log(f"Ejecutando: {command}")
            
            output = self.send_command_ssh(client, command)
            self._debug_log(f"Respuesta: {len(output)} bytes")
            
            # Validar output
            if not output or len(output) < 50:
                raise ValueError(f"Output sospechosamente corto: {len(output)} bytes")
            
            if "error" in output.lower() or "invalid" in output.lower():
                raise ValueError(f"Error en comando: {output[:200]}...")
            
            self._debug_log("✓ Output válido")
            
            # Guardar a archivo temporal
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(output)
            
            # Procesar (mover a archive/ + commit Git)
            # is_text=True para configs text, is_text=False para binarios
            return self.process_file(temp_path, is_text=True)
            
        finally:
            client.close()
            # Limpiar archivo temporal
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass
    
    # === OPCIÓN B: TELNET (alternativamente) ===
    # def backup(self):
    #     tn = self.connect_telnet()
    #     try:
    #         self._login_telnet(tn)
    #         self.send_command(tn, "show running-config")
    #         output = self.read_until(tn, [b"#", b">"], timeout=60)
    #         # ... procesar output ...
    #     finally:
    #         tn.close()
```

### Paso 3: Métodos Disponibles de la Clase Base

La clase `BackupVendor` provee estos métodos (no necesita reimplementarlos):

| Método | Uso |
|--------|-----|
| `self.connect_ssh()` | Conexión SSH usando credenciales del pool |
| `self.send_command_ssh(client, cmd)` | Ejecuta comando SSH y retorna output |
| `self.connect_telnet()` | Conexión Telnet al equipo |
| `self.send_command(tn, cmd)` | Envía comando por Telnet |
| `self.read_until(tn, prompts, timeout)` | Espera hasta recibir un prompt |
| `self.process_file(path, is_text)` | **Obligatorio**: Procesa el backup (archive + Git) |
| `self._debug_log(msg)` | Log visible en consola web en tiempo real |

### Paso 4: Propiedades Disponibles

| Propiedad | Descripción |
|-----------|-------------|
| `self.hostname` | Nombre del equipo (sysname) |
| `self.ip` | Dirección IP del equipo |
| `self.port` | Puerto de conexión (configurable) |
| `self.user` | Usuario actual del pool de credenciales |
| `self.password` | Contraseña actual |
| `self.credentials` | Lista completa de credenciales disponibles |

---

## 🧪 Testing del Plugin

### Antes de Cargar al Sistema

Cree un script de prueba para validar el plugin en ambiente controlado:

```python
# test_nuevo_vendor.py
# Ejecutar: python test_nuevo_vendor.py

import sys
import os

# Agregar el directorio del proyecto al path
sys.path.insert(0, '/opt/backup_system')
os.chdir('/opt/backup_system')

from core.db_manager import DBManager
from core.git_manager import GitManager
from vendors.nuevo_vendor import NuevoVendor  # Su plugin

# Configuración de prueba
device_info = {
    'hostname': 'TEST-DEVICE',
    'sysname': 'TEST-DEVICE',
    'ip': '192.168.1.100',       # IP del equipo de prueba
    'vendor': 'nuevo_vendor',
    'port': 22                    # Puerto si es diferente
}

credentials = [
    {'id': 'test', 'user': 'admin', 'pass': 'password123'}
]

# Crear instancia
db = DBManager()
git = GitManager()
plugin = NuevoVendor(device_info, db, git, credentials)

# Callback para ver logs en consola
plugin.log_callback = lambda msg: print(f"[LOG] {msg}")

# Ejecutar backup
print("=" * 50)
print("INICIANDO PRUEBA DE BACKUP")
print("=" * 50)

try:
    path, size, changed = plugin.backup()
    print(f"\n✅ ÉXITO!")
    print(f"   Archivo: {path}")
    print(f"   Tamaño:  {size} bytes")
    print(f"   Cambios: {'Sí' if changed else 'No'}")
except Exception as e:
    print(f"\n❌ ERROR: {e}")
    import traceback
    traceback.print_exc()
```

### Checklist Pre-Deploy

- [ ] El archivo está en `vendors/` con nombre `snake_case.py`
- [ ] La clase tiene nombre `TitleCase` correspondiente
- [ ] La clase hereda de `BackupVendor`
- [ ] El método `backup()` existe y retorna `(path, size, changed)`
- [ ] El script de test funciona correctamente
- [ ] El output del backup contiene datos válidos (no vacío)

---

## 📁 Agregar al Inventario

Una vez el plugin esté probado, agregue los dispositivos al inventario:

```yaml
groups:
  - name: Firewalls
    vendor: fortigate           # Nombre del archivo sin .py
    credential_ids:
      - fw_admin
    devices:
      - hostname: fw-principal
        ip: 10.0.0.1
        sysname: FW-PRINCIPAL
        criticidad: alta
        
      - hostname: fw-backup
        ip: 10.0.0.2
        sysname: FW-BACKUP
```

---

## 🔄 Deploy del Plugin

```bash
# 1. Copiar el plugin
sudo cp nuevo_vendor.py /opt/backup_system/vendors/

# 2. Reiniciar el servicio (para que auto-discovery detecte el nuevo plugin)
sudo systemctl restart backup_manager

# 3. Verificar en logs
sudo journalctl -u backup_manager -n 50 --no-pager | grep -i nuevo_vendor
```

---

## 🎨 Nombre Amigable en UI (Opcional)

El sistema mostrará el nombre del vendor en TitleCase automáticamente. Si desea un nombre personalizado, edite el diccionario en `templates/files.html`:

```javascript
// Buscar la variable vendorNames
const vendorNames = {
    'hp': 'HP', 
    'huawei': 'Huawei', 
    'zte_olt': 'OLT ZTE',
    'zteolt': 'OLT ZTE',
    'cisco': 'Cisco', 
    'mikrotik': 'MikroTik', 
    'fortigate': 'FortiGate',     // Agregar aquí
    'palo_alto': 'Palo Alto'      // Agregar aquí
};
```

---

## ⚠️ Troubleshooting

### El plugin no aparece en el sistema
1. Verifique que el archivo termine en `.py` y esté en `vendors/`
2. Verifique que el nombre de la clase sea correcto (TitleCase sin guiones bajos)
3. Reinicie el servicio: `systemctl restart backup_manager`
4. Revise logs: `journalctl -u backup_manager -f`

### Error "Unknown vendor"
El nombre en `inventory.yaml` debe coincidir exactamente con el nombre del archivo (sin `.py`):
- Archivo: `fortigate.py`
- Inventario: `vendor: fortigate` ✅
- Inventario: `vendor: FortiGate` ❌

### El equipo requiere SSH pero el plugin usa Telnet
Use `self.connect_ssh()` y `self.send_command_ssh()` en lugar de los métodos Telnet.

### Timeout durante backup
Aumente el timeout en las llamadas:
```python
output = self.send_command_ssh(client, command, timeout=120)  # 2 minutos
```

### El backup es binario (no texto)
Cambie el parámetro `is_text=False`:
```python
return self.process_file(temp_path, is_text=False)
```
Esto omite el versionado Git (que solo funciona con texto).

---

## 📚 Referencias

- Ver implementación SSH: `vendors/mikrotik.py`
- Ver implementación Telnet: `vendors/huawei.py`, `vendors/cisco.py`
- Ver implementación binaria: `vendors/zte_olt.py`
- Clase base: `vendors/base_vendor.py`
