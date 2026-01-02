# Control de Acceso (RBAC)

El sistema implementa un modelo de control de acceso basado en roles (RBAC) con
permisos granulares.

## Arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                          Usuario                                 │
│                                                                  │
│   username: "admin"                                              │
│   role: "superadmin"                                             │
│   permissions: []  ← vacío = usa permisos del rol               │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                            Rol                                   │
│                                                                  │
│   name: "superadmin"                                             │
│   permissions: ["view_dashboard", "manage_users", ...]          │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    has_permission(user, perm)                    │
│                                                                  │
│   1. ¿Usuario tiene permisos explícitos? → usar esos            │
│   2. Consultar permisos del rol desde DB                        │
│   3. Si rol no existe en DB → usar defaults hardcodeados        │
└─────────────────────────────────────────────────────────────────┘
```

## Roles del Sistema

### viewer (🔐 Sistema)
- Solo lectura
- Ver dashboard, archivos, comparaciones

### operator (🔐 Sistema)
- Ejecutar backups
- Ver inventario

### admin (🔐 Sistema)
- Editar inventario, vault, configuración
- Enviar email de prueba

### superadmin (🔐 Sistema)
- Todo lo anterior
- Gestionar usuarios y roles

## Permisos Disponibles

### 📖 Visualización
| Permiso | Descripción |
|---------|-------------|
| `view_dashboard` | Ver dashboard principal |
| `view_files` | Ver archivos de backup |
| `view_diff` | Ver diferencias entre versiones |
| `view_inventory` | Ver lista de dispositivos |
| `view_vault` | Ver credenciales (ocultas) |
| `view_settings` | Ver configuración del sistema |

### ✏️ Edición
| Permiso | Descripción |
|---------|-------------|
| `run_backup` | Ejecutar backups manualmente |
| `edit_inventory` | Modificar dispositivos |
| `edit_vault` | Modificar credenciales |
| `edit_settings` | Modificar configuración |

### 📧 Email
| Permiso | Descripción |
|---------|-------------|
| `test_email` | Enviar email de prueba desde config |

### 🔐 Administración
| Permiso | Descripción |
|---------|-------------|
| `manage_users` | Crear/editar/eliminar usuarios |
| `manage_roles` | Crear/editar/eliminar roles |

## Uso en Código

### Backend

```python
from flask import session

# Obtener usuario actual
user = get_current_user()

# Verificar permiso
if has_permission(user, 'edit_settings'):
    # permitido
else:
    # denegado

# Decorator para proteger endpoint
@app.route('/api/sensitive')
@requires_auth
@requires_permission('manage_users')
def api_sensitive():
    ...
```

### Templates (Jinja2)

```html
{% if can_edit_settings %}
    <button>Guardar</button>
{% else %}
    <button disabled title="Sin permisos">Guardar</button>
{% endif %}
```

## Crear Nuevo Rol

### Via UI
1. Ir a **Admin → Roles**
2. Click **Crear Rol**
3. Ingresar nombre, descripción, emoji
4. Seleccionar permisos
5. Guardar

### Via API
```bash
curl -X POST http://localhost:5000/api/roles \
  -H "Content-Type: application/json" \
  -d '{
    "name": "auditor",
    "emoji": "🔍",
    "description": "Solo lectura para auditoría",
    "permissions": ["view_dashboard", "view_files", "view_diff", "view_inventory"]
  }'
```

## Asignar Rol a Usuario

### Via UI
1. Ir a **Admin → Usuarios**
2. Click en el usuario
3. Seleccionar rol del dropdown
4. Guardar

### Via API
```bash
curl -X PUT http://localhost:5000/api/users/5 \
  -H "Content-Type: application/json" \
  -d '{"role": "auditor"}'
```

## Permisos Explícitos por Usuario

Un usuario puede tener permisos adicionales a los de su rol:

```python
# Usuario con rol "viewer" pero permiso extra
user = {
    "username": "auditor_especial",
    "role": "viewer",
    "permissions": ["view_vault"]  # Explícito: puede ver vault
}
```

## Rate Limiting

Algunos endpoints tienen rate limiting para prevenir abuso:

| Endpoint | Límite |
|----------|--------|
| `POST /api/settings/test-email` | 1 cada 60 segundos |
| `POST /api/backup/run` | 1 cada 30 segundos |

Si se excede:
```json
{
  "status": "error",
  "message": "Esperá X segundos antes de volver a intentar."
}
```
Status code: `429 Too Many Requests`

## Logging de Acceso

Las acciones importantes se loguean:

```
Test email: user=admin role=superadmin ip=192.168.1.10 result=OK
Settings update: user=admin keys=['smtp_host', 'smtp_port']
Backup started: user=operator target=all
```

## Troubleshooting

### Verificar permisos de un usuario
```python
from core.config_manager import get_config_manager
cfg = get_config_manager()
user = cfg.get_user_by_id(1)
role = cfg.get_role(user['role'])
print(f"Permisos del rol: {role['permissions']}")
```

### Verificar permisos de un rol
```bash
sqlite3 backup_system.db \
  "SELECT permissions FROM roles WHERE name='superadmin';"
```

### Usuario sin acceso a algo que debería tener
1. Verificar que el rol tenga el permiso
2. Verificar que el usuario tenga ese rol
3. Cerrar sesión y volver a entrar
4. Revisar logs para errores
