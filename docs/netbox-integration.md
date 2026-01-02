# Integración con NetBox

Esta guía explica cómo integrar el Backup System con NetBox como fuente de inventario.

## Requisitos Previos

1. **NetBox instalado y funcionando**
2. **API habilitada** en NetBox
3. **Token de API** con permisos de lectura
4. **Custom fields** creados (ver abajo)

## Paso 1: Crear Custom Fields en NetBox

Ir a **Admin → Custom Fields** y crear:

### backup_schedule
- **Object types**: Device
- **Type**: Text
- **Label**: Backup Schedule
- **Description**: Horarios de backup en formato HH:MM separados por coma
- **Regex**: `^(\d{2}:\d{2})(,\s*\d{2}:\d{2})*$|^$`

### backup_enabled
- **Object types**: Device
- **Type**: Boolean
- **Label**: Backup Enabled
- **Default**: True

## Paso 2: Crear Tag de Filtrado

Ir a **Organization → Tags** y crear:

- **Name**: backup-enabled
- **Color**: Green
- **Description**: Dispositivos que deben ser respaldados

Aplicar este tag a todos los dispositivos que quieras incluir en los backups.

## Paso 3: Obtener Token de API

1. Ir a **Admin → API Tokens**
2. Click **Add** → **Create Token**
3. Copiar el token generado (solo se muestra una vez)

## Paso 4: Configurar Backup System

### Opción A: Via UI

1. Ir a **Configuración**
2. En la sección **Sistema**, buscar:
   - **Inventory Source**: `netbox`
   - **NetBox URL**: `https://netbox.example.com`
   - **NetBox Token**: `<tu-token>`
   - **NetBox Filter Tag**: `backup-enabled`
3. Guardar

### Opción B: Via API

```bash
curl -X PUT http://localhost:5000/api/settings \
  -H "Content-Type: application/json" \
  -d '{
    "inventory_source": "netbox",
    "netbox_url": "https://netbox.example.com",
    "netbox_token": "0123456789abcdef...",
    "netbox_filter_tag": "backup-enabled"
  }'
```

### Opción C: Via SQLite (directo)

```sql
UPDATE settings SET value = 'netbox' WHERE key = 'inventory_source';
UPDATE settings SET value = 'https://netbox.example.com' WHERE key = 'netbox_url';
UPDATE settings SET value = '0123456789...' WHERE key = 'netbox_token';
UPDATE settings SET value = 'backup-enabled' WHERE key = 'netbox_filter_tag';
```

## Paso 5: Instalar Dependencia

```bash
pip install pynetbox
```

## Paso 6: Reiniciar Servicio

```bash
systemctl restart backup-web
```

## Paso 7: Verificar

```bash
# Ver logs
journalctl -u backup-web -f

# Verificar inventario
curl -s http://localhost:5000/api/inventory | jq '.groups | length'
```

## Mapeo de Campos

| NetBox | Backup System | Notas |
|--------|---------------|-------|
| `device.name` | `sysname` | Identificador único |
| `device.primary_ip4.address` | `ip` | Se extrae sin máscara |
| `device.device_type.manufacturer.name` | `vendor` | Fabricante |
| `device.device_type.model` | `modelo` | Modelo del equipo |
| `device.site.name` | `grupo` | Agrupación por sitio |
| `device.device_type.slug` | `tipo` | Tipo de dispositivo |
| `cf.backup_schedule` | `schedule` | Custom field |
| `cf.backup_enabled` | `backup_enabled` | Custom field |
| `device.tags` | `tags` | Lista de tags |

## Herencia de Schedules

El sistema sigue la misma lógica de herencia:

```
Device schedule (cf.backup_schedule) 
    → Model schedule (schedule_model_<vendor>_<modelo>)
        → Vendor schedule (schedule_vendor_<vendor>)
            → Global schedule
```

Si `cf.backup_schedule` está vacío en NetBox, hereda del nivel superior.

## Troubleshooting

### Error: "pynetbox is not installed"

```bash
pip install pynetbox
systemctl restart backup-web
```

### Error: "NetBox config incomplete"

Verificar que todos los settings estén configurados:
```bash
sqlite3 /opt/backup_system/backup_system.db \
  "SELECT * FROM settings WHERE key LIKE 'netbox%';"
```

### No aparecen dispositivos

1. Verificar que los dispositivos tengan el tag `backup-enabled`
2. Verificar que tengan `primary_ip4` asignada
3. Verificar que `status = active`

### Logs de debug

```bash
# Habilitar debug
sqlite3 /opt/backup_system/backup_system.db \
  "UPDATE settings SET value = 'DEBUG' WHERE key = 'log_level';"

systemctl restart backup-web
journalctl -u backup-web -f
```

## Rollback a YAML

Si necesitás volver al inventario YAML:

```bash
sqlite3 /opt/backup_system/backup_system.db \
  "UPDATE settings SET value = 'yaml' WHERE key = 'inventory_source';"

systemctl restart backup-web
```

## Webhooks (Futuro)

En una versión futura, el sistema podrá recibir webhooks de NetBox para:
- Sincronizar automáticamente cuando cambia un dispositivo
- Ejecutar backup inmediato cuando se agrega un device con el tag

Endpoint planeado:
```
POST /api/inventory/sync
Content-Type: application/json
X-NetBox-Signature: <hmac>
```
