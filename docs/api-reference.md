# API Reference

El sistema expone una API REST para automatización e integración.

## Autenticación

### Session (Web UI)
El login crea una sesión que se mantiene con cookies.

### API Token (Automatización)
```bash
curl -H "Authorization: Bearer <token>" http://localhost:5000/api/...
```

Para obtener un token, crearlo desde Admin → Usuarios → API Tokens.

---

## Endpoints

### Dashboard

#### GET /api/dashboard/stats
Obtener estadísticas del dashboard.

**Respuesta:**
```json
{
  "total_devices": 50,
  "last_backup": "2026-01-02T02:00:00",
  "success_rate": 98.5,
  "pending_backups": 2
}
```

---

### Backup

#### POST /api/backup/run
Ejecutar backup manualmente.

**Permisos:** `run_backup`

**Body (opcional):**
```json
{
  "target": "all" | "vendor:Huawei" | "group:Core" | "device:SW-01"
}
```

**Respuesta:**
```json
{
  "status": "ok",
  "message": "Backup iniciado",
  "job_id": "abc123"
}
```

#### GET /api/backup/status/<job_id>
Ver estado de un backup en progreso.

**Respuesta:**
```json
{
  "status": "running" | "completed" | "failed",
  "progress": 75,
  "devices_total": 50,
  "devices_completed": 38,
  "errors": []
}
```

---

### Inventario

#### GET /api/inventory
Obtener inventario completo.

**Permisos:** `view_inventory`

**Respuesta:**
```json
{
  "groups": [
    {
      "name": "Core",
      "vendor": "Huawei",
      "devices": [
        {
          "sysname": "SW-CORE-01",
          "ip": "192.168.1.1",
          "modelo": "S5720"
        }
      ]
    }
  ]
}
```

#### GET /api/inventory/devices
Obtener lista plana de dispositivos.

**Respuesta:**
```json
{
  "devices": [
    {"sysname": "SW-01", "ip": "192.168.1.1", "vendor": "Huawei"},
    {"sysname": "SW-02", "ip": "192.168.1.2", "vendor": "Cisco"}
  ]
}
```

#### POST /api/inventory/devices
Agregar dispositivo.

**Permisos:** `edit_inventory`

**Body:**
```json
{
  "sysname": "SW-NEW-01",
  "ip": "192.168.1.100",
  "vendor": "Huawei",
  "modelo": "S5720",
  "grupo": "Acceso"
}
```

#### PUT /api/inventory/devices/<sysname>
Actualizar dispositivo.

#### DELETE /api/inventory/devices/<sysname>
Eliminar dispositivo.

---

### Archivos / Historial

#### GET /api/files
Listar dispositivos con backups.

**Permisos:** `view_files`

**Respuesta:**
```json
{
  "devices": ["SW-01", "SW-02", "RT-01"]
}
```

#### GET /api/files/<sysname>
Listar versiones de un dispositivo.

**Respuesta:**
```json
{
  "versions": [
    {"date": "2026-01-02", "commit": "abc123", "size": 15420},
    {"date": "2026-01-01", "commit": "def456", "size": 15380}
  ]
}
```

#### GET /api/files/<sysname>/<commit>
Obtener contenido de una versión.

**Respuesta:**
```json
{
  "content": "# Configuration...",
  "date": "2026-01-02T02:05:00",
  "commit": "abc123"
}
```

#### GET /api/diff/<sysname>?from=<commit>&to=<commit>
Comparar dos versiones.

**Permisos:** `view_diff`

**Respuesta:**
```json
{
  "diff": "--- a/config\n+++ b/config\n@@ -10,3 +10,4 @@\n...",
  "additions": 5,
  "deletions": 2
}
```

---

### Configuración

#### GET /api/settings
Obtener configuración.

**Permisos:** `view_settings`

**Respuesta:**
```json
{
  "backup_enabled": "true",
  "global_schedule": "02:00",
  "smtp_host": "smtp.example.com",
  ...
}
```

#### PUT /api/settings
Actualizar configuración.

**Permisos:** `edit_settings`

**Body:**
```json
{
  "global_schedule": "02:00, 14:00",
  "smtp_host": "nuevo-smtp.example.com"
}
```

#### POST /api/settings/test-email
Enviar email de prueba.

**Permisos:** `test_email`
**Rate limit:** 1 cada 60 segundos

**Respuesta:**
```json
{
  "status": "ok",
  "message": "Email enviado correctamente a admin@example.com"
}
```

---

### Usuarios

#### GET /api/users
Listar usuarios.

**Permisos:** `manage_users`

#### POST /api/users
Crear usuario.

**Body:**
```json
{
  "username": "nuevo_usuario",
  "password": "password123",
  "role": "operator",
  "email": "user@example.com"
}
```

#### PUT /api/users/<id>
Actualizar usuario.

#### DELETE /api/users/<id>
Eliminar usuario.

---

### Roles

#### GET /api/roles
Listar roles.

**Permisos:** `manage_roles`

#### POST /api/roles
Crear rol.

**Body:**
```json
{
  "name": "auditor",
  "emoji": "🔍",
  "description": "Solo lectura para auditoría",
  "permissions": ["view_dashboard", "view_files", "view_diff"]
}
```

#### PUT /api/roles/<id>
Actualizar rol.

#### DELETE /api/roles/<id>
Eliminar rol (solo roles no-sistema).

---

### Vault (Credenciales)

#### GET /api/vault
Listar credenciales (passwords ocultos).

**Permisos:** `view_vault`

#### POST /api/vault
Agregar credencial.

**Permisos:** `edit_vault`

**Body:**
```json
{
  "name": "huawei_core",
  "username": "admin",
  "password": "secret123",
  "tags": ["huawei", "core"]
}
```

---

## Códigos de Estado

| Código | Significado |
|--------|-------------|
| 200 | OK |
| 201 | Created |
| 400 | Bad Request (validación fallida) |
| 401 | Unauthorized (no autenticado) |
| 403 | Forbidden (sin permisos) |
| 404 | Not Found |
| 429 | Too Many Requests (rate limit) |
| 500 | Internal Server Error |

## Errores

```json
{
  "status": "error",
  "message": "Descripción del error en español"
}
```

## Rate Limiting

Algunos endpoints tienen límites:
- `test-email`: 1 cada 60s
- `backup/run`: 1 cada 30s

Si se excede:
```json
{
  "status": "error",
  "message": "Esperá X segundos antes de volver a intentar."
}
```
