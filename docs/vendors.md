# Vendors y Plugins

El sistema utiliza una arquitectura de plugins para soportar múltiples fabricantes. Cada vendor es un módulo Python independiente en la carpeta `vendors/` que hereda de una clase base común.

## Arquitectura

El `BackupEngine` carga dinámicamente los plugins basándose en el nombre del vendor configurado en el inventario.

```
cargador dinámico (engine.py)
       │
       ▼
  vendors/<vendor_name>.py  →  Clase <VendorName>(BackupVendor)
                                     │
                                     ▼
                                  .backup()
```

### Reglas de Carga
1. **Archivo**: Debe existir en `vendors/` con el nombre en minúsculas (ej: `asga.py`).
2. **Clase**: Debe contener una clase con el nombre en TitleCase (ej: `Asga`).
   - Para nombres con guión bajo: `zte_olt.py` → `class ZteOlt`.
3. **Herencia**: La clase debe heredar de `vendors.base_vendor.BackupVendor`.

---

## Vendors Soportados

| Vendor | Archivo | Protocolo | Método |
|--------|---------|-----------|--------|
| **Huawei** | `vendors/huawei.py` | Telnet | `tftp put` (zip) |
| **Cisco** | `vendors/cisco.py` | Telnet | `copy running-config tftp` |
| **HP** | `vendors/hp.py` | Telnet | `copy startup-config tftp` |
| **ZTE OLT** | `vendors/zte_olt.py` | Telnet | `file upload ... tftp` |
| **ASGA** | `vendors/asga.py` | Telnet | `copy running-config tftp` |

---

## 🛠️ Guía: Agregar Nuevo Vendor

Siga estos pasos para integrar un nuevo fabricante al sistema.

### 1. Crear el Archivo del Plugin

Cree un archivo nuevo en `vendors/` (ej: `vendors/mikrotik.py`).

**Plantilla Base:**

```python
import time
import os
from vendors.base_vendor import BackupVendor
from settings import TFTP_ROOT
from core.config_manager import get_config_manager

class Mikrotik(BackupVendor):
    """
    Plugin para Mikrotik via Telnet + TFTP.
    """
    
    def backup(self):
        """
        Implementación del flujo de backup.
        Debe devolver: (ruta_archivo, tamaño, hubo_cambios)
        """
        # 1. Obtener servidor TFTP
        config = get_config_manager()
        tftp_server = config.get_setting('tftp_server') or '127.0.0.1'
        
        # 2. Conectar (Telnet)
        # base_vendor provee connect_telnet()
        tn = self.connect_telnet()
        
        # 3. Autenticación (usando pool de credenciales)
        self._login(tn)
        
        # 4. Ejecutar comando de backup
        # Ej: Mikrotik export a archivo local y luego upload TFTP
        # Nota: Ajustar según comandos reales del equipo
        filename = f"{self.hostname}.rsc"
        cmd = f"/export file={filename}"
        self.send_command(tn, cmd)
        
        # 5. Transferir a TFTP
        # ... lógica de transferencia ...
        
        # 6. Procesar archivo resultante
        # Busca el archivo en TFTP_ROOT y lo procesa
        file_path = os.path.join(TFTP_ROOT, filename)
        return self.process_file(file_path, is_text=True)

    def _login(self, tn):
        """Helper para iterar credenciales."""
        # Ver implementación completa en cisco.py o huawei.py
        pass
```

### 2. Métodos Útiles (clase `BackupVendor`)

La clase base provee herramientas comunes:

- **`self.connect_telnet()`**: Establece conexión y devuelve objeto telnet.
- **`self.read_until(tn, lista_prompts, timeout)`**: Espera hasta recibir uno de los prompts.
- **`self.send_command(tn, comando)`**: Envía comando + `\n` y lo loguea con debug.
- **`self.process_file(path, is_text)`**: Mueve el archivo al archivo histórico, actualiza el puntero "latest" y hace commit en Git.
- **`self._debug_log(msg)`**: Escribe en el log del sistema y en la consola web en tiempo real.

### 3. Configuración en Web UI (Opcional)

Para que el vendor aparezca con un nombre "amigable" en la interfaz web, edite `web_app.py`:

```python
# Buscar el diccionario vendor_names (aprox línea 2070)
vendor_names = {
    'hp': 'HP',
    'huawei': 'Huawei',
    # ...
    'mikrotik': 'MikroTik RouterOS',  # Agregar aquí
    'asga': 'ASGA'
}
```

### 4. Prueba y Verificación

Puede probar el plugin sin ejecutar toda la web usando un script temporal:

```python
# test_vendor.py
from core.db_manager import DBManager
from core.git_manager import GitManager
from vendors.mikrotik import Mikrotik

# Mock de objetos
db = DBManager()
git = GitManager()

device_info = {
    'hostname': 'Test-Router',
    'ip': '192.168.1.50',
    'vendor': 'mikrotik'
}
creds = [{'user': 'admin', 'pass': '1234', 'id': 'test'}]

plugin = Mikrotik(device_info, db, git, creds)
plugin.log_callback = print  # Ver logs en consola

try:
    path, size, changed = plugin.backup()
    print("Éxito!")
except Exception as e:
    print(f"Error: {e}")
```

---

## Troubleshooting Común

### El equipo no soporta TFTP
Si el equipo solo soporta FTP, puede usar la librería estándar `ftplib` de Python dentro del método `backup()`. Ver ejemplo en `vendors/zte_olt.py`.

### El equipo requiere SSH
Actualmente la clase base solo provee helper para Telnet. Para SSH, debe importar una librería externa (como `paramiko` o invocar el binario `ssh` con `subprocess`), pero esto requiere instalar dependencias adicionales en el entorno virtual.

### Problemas de Tiempos (Timeout)
Si el backup es grande y tarda en generarse, aumente el `timeout` en las llamadas a `self.read_until()`.

```python
# Esperar hasta 120 segundos
self.read_until(tn, ["#"], timeout=120)
```
