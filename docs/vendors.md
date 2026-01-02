# Vendors

El sistema soporta múltiples fabricantes de equipos de red. Cada vendor tiene
su propia implementación para manejar las particularidades de conexión y backup.

## Arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                       VendorFactory                              │
│                                                                  │
│   create(vendor_name) → VendorBase implementation               │
└──────────────────────────────┬──────────────────────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│     Huawei      │  │     Cisco       │  │       HP        │
│   (SSH+TFTP)    │  │   (SSH+TFTP)    │  │   (SSH+TFTP)    │
└─────────────────┘  └─────────────────┘  └─────────────────┘
          │
          ▼
┌─────────────────┐
│     ZTE OLT     │
│   (SSH+FTP)     │
└─────────────────┘
```

## Vendors Soportados

### Huawei (`vendors/huawei.py`)

**Modelos probados:**
- S5720 series
- S6720 series
- S12700 series
- NE40E series (routers)

**Método de backup:**
1. Conectar vía SSH
2. Ejecutar: `save` (guardar config)
3. Ejecutar: `tftp <server_ip> put vrpcfg.zip <filename>`
4. El archivo se recibe en el servidor TFTP

**Archivo resultante:** `vrpcfg.zip` (comprimido)

**Comandos ejecutados:**
```
screen-length 0 temporary
save
Y
tftp 192.168.1.100 put vrpcfg.zip SW-CORE-01_20260102_020000.zip
quit
```

---

### Cisco (`vendors/cisco.py`)

**Modelos probados:**
- Catalyst 9200/9300/9500
- Catalyst 2960/3560/3750
- ISR routers

**Método de backup:**
1. Conectar vía SSH
2. Ejecutar: `copy running-config tftp://server/filename`
3. El archivo se recibe en el servidor TFTP

**Archivo resultante:** Texto plano

**Comandos ejecutados:**
```
terminal length 0
copy running-config tftp://192.168.1.100/SW-ACC-01_20260102_020000.cfg

[confirmar]
```

---

### HP (`vendors/hp.py`)

**Modelos probados:**
- ProCurve series
- Aruba switches

**Método de backup:**
1. Conectar vía SSH
2. Ejecutar: `copy startup-config tftp server filename`

**Archivo resultante:** Texto plano

**Comandos ejecutados:**
```
no page
copy startup-config tftp 192.168.1.100 SW-HP-01_20260102_020000.cfg
```

---

### ZTE OLT (`vendors/zte_olt.py`)

**Modelos probados:**
- C300
- C320
- C600

**Método de backup:**
1. Conectar vía SSH
2. Generar backup: `backup database`
3. Transferir vía FTP (no TFTP)

**Archivo resultante:** Archivo de base de datos binario

**Particularidades:**
- Usa FTP en lugar de TFTP
- El backup es un archivo binario, no texto
- Requiere credenciales FTP configuradas

---

## Configuración

### Servidor TFTP/FTP

En **Configuración → Sistema**:
- **Servidor TFTP/FTP**: IP pública que ven los equipos

Esta IP debe ser accesible desde los dispositivos de red.

### Credenciales

Las credenciales se almacenan en el Vault y se asocian por:
- Vendor
- Grupo
- Device específico

El sistema busca credenciales en orden de especificidad:
1. Credencial específica del device
2. Credencial del grupo
3. Credencial del vendor
4. Credencial por defecto

---

## Agregar Nuevo Vendor

### 1. Crear archivo en `vendors/`

```python
# vendors/mikrotik.py

from vendors.base import VendorBase
import paramiko

class Mikrotik(VendorBase):
    def __init__(self):
        super().__init__()
        self.vendor_name = 'Mikrotik'
    
    def backup(self, device, credentials):
        """
        Ejecutar backup de un dispositivo Mikrotik.
        
        Args:
            device: Dict con sysname, ip, modelo, etc.
            credentials: Dict con username, password
            
        Returns:
            Tuple (success: bool, message: str, filename: str)
        """
        try:
            # 1. Conectar SSH
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                device['ip'],
                username=credentials['username'],
                password=credentials['password'],
                timeout=30
            )
            
            # 2. Ejecutar comandos de backup
            stdin, stdout, stderr = ssh.exec_command('/export')
            config = stdout.read().decode('utf-8')
            
            # 3. Guardar archivo
            filename = self.generate_filename(device)
            filepath = self.save_config(device, config, filename)
            
            ssh.close()
            return True, "Backup exitoso", filename
            
        except Exception as e:
            return False, str(e), None
```

### 2. Registrar en VendorFactory

```python
# vendors/__init__.py

from vendors.mikrotik import Mikrotik

VENDOR_MAP = {
    'huawei': Huawei,
    'cisco': Cisco,
    'hp': Hp,
    'zte': ZteOlt,
    'mikrotik': Mikrotik,  # Nuevo
}
```

### 3. Agregar dispositivos al inventario

```yaml
groups:
  - name: "MikroTik"
    vendor: "Mikrotik"
    devices:
      - sysname: "RB-CORE-01"
        ip: "192.168.10.1"
        modelo: "CCR1036"
```

---

## Troubleshooting

### Timeout de conexión
- Verificar conectividad: `ping <ip>`
- Verificar puerto SSH: `nc -zv <ip> 22`
- Verificar credenciales manualmente

### TFTP no recibe archivo
- Verificar que tftpd esté corriendo
- Verificar permisos del directorio TFTP
- Verificar firewall (UDP 69)

### Error en comandos
- Revisar logs: `journalctl -u backup-web -f`
- Probar comandos manualmente vía SSH
- Verificar versión de firmware del equipo

### Logs de vendor
```bash
# Ver logs de un backup específico
grep "SW-CORE-01" /var/log/backup_system.log
```
