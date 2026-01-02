# Inventory Providers

El sistema usa una capa de abstracción para el inventario de dispositivos, permitiendo
integrar diferentes fuentes de datos sin modificar el código del motor de backups.

## Arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                     InventoryProvider (ABC)                      │
│                                                                  │
│   get_all_devices()        → List[Device]                       │
│   get_devices_by_vendor()  → List[Device]                       │
│   get_devices_by_group()   → List[Device]                       │
│   get_unique_vendors()     → List[str]                          │
│   get_raw_inventory()      → Dict (legacy compatibility)        │
└──────────────────────────────┬──────────────────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
┌──────────────────┐ ┌─────────────────┐ ┌──────────────────┐
│YamlInventoryProv │ │NetBoxInventory  │ │ Future Providers │
│  (inventory.yaml)│ │Provider (API)   │ │  (webhook, etc)  │
└──────────────────┘ └─────────────────┘ └──────────────────┘
```

## Device Model

Todos los providers devuelven objetos `Device` con una estructura común:

```python
from core.models import Device

device = Device(
    sysname='SW-CORE-01',      # Identificador único (inmutable)
    ip='192.168.1.1',          # IP de gestión
    vendor='Huawei',           # Fabricante
    modelo='S5720-28X-SI',     # Modelo
    grupo='Core',              # Agrupación lógica
    tipo='switch',             # Tipo de dispositivo
    criticidad='alta',         # Nivel de criticidad
    schedule='02:00, 14:00',   # Schedule específico (opcional)
    backup_enabled=True,       # Habilitado para backup
    tags=['produccion', 'datacenter'],  # Tags adicionales
)
```

## Providers Disponibles

### 1. YamlInventoryProvider (Default)

Lee dispositivos desde `inventory.yaml` en la raíz del proyecto.

**Configuración:**
```
inventory_source = yaml
```

**Formato del archivo:**
```yaml
groups:
  - name: "Core"
    vendor: "Huawei"
    devices:
      - sysname: "SW-CORE-01"
        ip: "192.168.1.1"
        modelo: "S5720-28X-SI"
        criticidad: "alta"
        
      - sysname: "SW-CORE-02"
        ip: "192.168.1.2"
        modelo: "S5720-28X-SI"

  - name: "Acceso"
    vendor: "Cisco"
    devices:
      - sysname: "SW-ACC-01"
        ip: "192.168.2.1"
        modelo: "C9200L-24T-4G"
```

**Características:**
- ✅ Sin dependencias externas
- ✅ Caching automático (recarga si el archivo cambia)
- ✅ Herencia de vendor/grupo desde la sección padre
- ⚠️ Requiere edición manual para cambios

### 2. NetBoxInventoryProvider

Consulta dispositivos desde NetBox API.

**Configuración:**
```
inventory_source = netbox
netbox_url = https://netbox.example.com
netbox_token = 0123456789abcdef...
netbox_filter_tag = backup-enabled
```

**Custom Fields requeridos en NetBox:**
- `backup_schedule` (text): Horario HH:MM o CSV
- `backup_enabled` (boolean): Si está habilitado

**Mapeo de campos:**
| NetBox                          | Device      |
|---------------------------------|-------------|
| `device.name`                   | `sysname`   |
| `device.primary_ip4.address`    | `ip`        |
| `device.device_type.manufacturer.name` | `vendor` |
| `device.device_type.model`      | `modelo`    |
| `device.site.name`              | `grupo`     |
| `device.device_type.slug`       | `tipo`      |
| `device.custom_fields.backup_schedule` | `schedule` |
| `device.custom_fields.backup_enabled` | `backup_enabled` |
| `device.tags`                   | `tags`      |

**Características:**
- ✅ Fuente de verdad centralizada
- ✅ Cambios reflejados automáticamente
- ✅ Filtrado por tag
- ⚠️ Requiere `pynetbox` instalado
- ⚠️ Depende de disponibilidad de NetBox

## Uso en Código

### Obtener el Provider

```python
from core.inventory_provider import get_inventory_provider

# Obtiene el provider configurado (singleton)
provider = get_inventory_provider()

# Obtener todos los dispositivos
devices = provider.get_all_devices()

# Filtrar por vendor
huawei_devices = provider.get_devices_by_vendor('Huawei')

# Obtener vendors únicos
vendors = provider.get_unique_vendors()
```

### Resetear Cache

```python
from core.inventory_provider import reset_inventory_provider

# Forzar recarga (útil si cambió la configuración)
reset_inventory_provider()
```

## Crear un Provider Personalizado

Para crear un nuevo provider (ej: Webhook, CSV, etc.):

```python
from core.inventory_provider import InventoryProvider
from core.models import Device

class CustomInventoryProvider(InventoryProvider):
    def get_all_devices(self) -> List[Device]:
        # Tu lógica aquí
        return [Device(...), ...]
    
    def get_devices_by_vendor(self, vendor: str) -> List[Device]:
        return [d for d in self.get_all_devices() 
                if d.vendor.lower() == vendor.lower()]
    
    # ... implementar otros métodos
```

## Migración entre Providers

1. **Verificar datos**: Exportar inventario actual
2. **Configurar nuevo provider**: Agregar settings
3. **Probar**: Cambiar `inventory_source` y verificar
4. **Rollback**: Si falla, volver a `yaml`

```bash
# Exportar inventario actual a JSON
curl -s http://localhost:5000/api/inventory | jq > backup_inventory.json

# Cambiar a NetBox
# (editar settings en UI o DB)

# Verificar cantidad de devices
curl -s http://localhost:5000/api/inventory | jq '.groups[].devices | length'
```
