# Sistema de Auditoría

El sistema incluye un registro de auditoría completo (estilo Bookstack) que rastrea todas las acciones importantes.

## Acceso

**URL**: `/admin/audit`

**Permisos requeridos**: `view_logs`

## Eventos Auditados

### Autenticación
| Evento | Descripción |
|--------|-------------|
| `auth_login` | Inicio de sesión exitoso |
| `auth_logout` | Cierre de sesión |
| `auth_failed` | Intento de login fallido |

### Inventario
| Evento | Descripción |
|--------|-------------|
| `device_create` | Dispositivo creado |
| `device_update` | Dispositivo modificado |
| `device_delete` | Dispositivo eliminado |
| `device_enable` | Dispositivo habilitado para backup |
| `device_disable` | Dispositivo deshabilitado (con motivo) |
| `group_create` | Grupo creado |
| `group_update` | Grupo modificado |
| `group_delete` | Grupo eliminado |

### Vault
| Evento | Descripción |
|--------|-------------|
| `credential_create` | Credencial creada |
| `credential_update` | Credencial modificada |
| `credential_delete` | Credencial eliminada |

### Usuarios
| Evento | Descripción |
|--------|-------------|
| `user_create` | Usuario creado |
| `user_update` | Usuario modificado |
| `user_delete` | Usuario eliminado |

## Estructura de Datos

Cada registro de auditoría contiene:

```json
{
  "id": 123,
  "timestamp": "2026-01-20 10:30:00",
  "user_id": 1,
  "username": "admin",
  "event_type": "device_disable",
  "event_category": "inventory",
  "entity_type": "device",
  "entity_id": "SW-CORE-01",
  "entity_name": "Switch Core Principal",
  "details": {"reason": "Equipo en mantenimiento"},
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0..."
}
```

## API

### Listar Logs

```
GET /api/audit?page=1&per_page=20
```

**Filtros disponibles**:
- `event_type`: Tipo de evento específico
- `user_id`: ID del usuario
- `username`: Nombre de usuario (búsqueda parcial)
- `ip_address`: Dirección IP (búsqueda parcial)
- `date_from`: Fecha inicio (YYYY-MM-DD)
- `date_to`: Fecha fin (YYYY-MM-DD)
- `entity_type`: Tipo de entidad (device, group, user)
- `search`: Búsqueda en nombre/detalles

**Respuesta**:
```json
{
  "logs": [...],
  "total": 150,
  "page": 1,
  "per_page": 20,
  "total_pages": 8
}
```

### Tipos de Eventos

```
GET /api/audit/event-types
```

Retorna lista de todos los tipos de eventos disponibles.

### Usuarios en Logs

```
GET /api/audit/users
```

Retorna lista de usuarios que aparecen en los logs.

## UI

La interfaz de auditoría incluye:

- **Filtros avanzados**: Tipo de evento, rango de fechas, usuario, IP
- **Paginación**: 20/50/100 elementos por página
- **Avatares coloreados**: Basados en hash del username (estilo Bookstack)
- **Badges de eventos**: Coloreados por categoría

## Retención

Los logs de auditoría pueden limpiarse automáticamente:

```python
from core.db_manager import DBManager
db = DBManager()
db.delete_old_audit_logs(days=90)  # Eliminar logs más viejos de 90 días
```

## Integración en Código

Para registrar eventos desde cualquier endpoint:

```python
from web_app import log_audit

# Ejemplo básico
log_audit('device_create', entity_type='device', entity_id='SW-01', entity_name='Switch 01')

# Con detalles adicionales
log_audit('device_disable', 
          entity_type='device', 
          entity_id='SW-01',
          entity_name='Switch 01',
          details={'reason': 'Mantenimiento programado'})
```

La función `log_audit()` automáticamente captura:
- Usuario actual de la sesión
- Dirección IP del request
- User-Agent del navegador
