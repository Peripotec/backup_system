# Arquitectura del Sistema

## Visión General

```
┌─────────────────────────────────────────────────────────────────┐
│                         Web UI (Flask)                          │
│                    templates/ + static/                         │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                        web_app.py                                │
│              REST API + Auth + RBAC + Session                    │
└───────────────────────────┬─────────────────────────────────────┘
                            │
          ┌─────────────────┼─────────────────┐
          ▼                 ▼                 ▼
┌─────────────────┐ ┌─────────────┐ ┌─────────────────┐
│ ConfigManager   │ │BackupEngine │ │    Notifier     │
│   (SQLite)      │ │             │ │    (SMTP)       │
└─────────────────┘ └──────┬──────┘ └─────────────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
┌─────────────────┐ ┌─────────────┐ ┌─────────────────┐
│InventoryProvider│ │VendorFactory│ │  Git Storage    │
│ (YAML/NetBox)   │ │             │ │  (versioning)   │
└─────────────────┘ └──────┬──────┘ └─────────────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
┌─────────────────┐ ┌─────────────┐ ┌─────────────────┐
│     Huawei      │ │    Cisco    │ │    ZTE OLT      │
│   (SSH/TFTP)    │ │ (SSH/TFTP)  │ │   (SSH/FTP)     │
└─────────────────┘ └─────────────┘ └─────────────────┘
```

## Componentes Principales

### 1. Web Application (`web_app.py`)

- **Framework**: Flask
- **Autenticación**: Session-based + API tokens
- **RBAC**: Permisos granulares por rol
- **Endpoints**: `/api/*` REST + páginas HTML

### 2. Config Manager (`core/config_manager.py`)

- **Storage**: SQLite (`backup_system.db`)
- **Tablas**: `settings`, `users`, `roles`
- **Singleton**: Acceso global vía `get_config_manager()`

### 3. Backup Engine (`core/engine.py`)

- **Orquestación**: Ejecuta backups en paralelo
- **Scheduling**: Herencia de schedules (device→model→vendor→global)
- **Vendor Factory**: Instancia el handler correcto por vendor

### 4. Inventory Provider (`core/inventory_provider.py`)

- **Abstracción**: Interface común para YAML y NetBox
- **Factory**: `get_inventory_provider()` según config
- **Caching**: Recargar automático si el archivo cambia

### 5. Vendors (`vendors/*.py`)

- **Base class**: `VendorBase` con interfaz común
- **Implementaciones**: Huawei, Cisco, HP, ZTE
- **Conexión**: SSH via Paramiko/Netmiko
- **Transfer**: TFTP para Huawei/Cisco/HP, FTP para ZTE

## Flujo de Ejecución

### Backup Manual

```
Usuario → UI → POST /api/backup/run
                    │
                    ▼
              BackupEngine.run_all()
                    │
                    ▼
              InventoryProvider.get_all_devices()
                    │
                    ▼
              Para cada device:
                VendorFactory.create(device.vendor)
                    │
                    ▼
                vendor.backup(device)
                    │
                    ▼
                Git commit + push
                    │
                    ▼
              Notifier.send_summary()
```

### Backup Programado

```
systemd timer (cada minuto)
        │
        ▼
  scheduled_runner.py
        │
        ▼
  ¿Hay schedule para este minuto?
        │
    No ─┴─ Yes
    │       │
    │       ▼
    │   BackupEngine.run_scheduled(HH:MM)
    │       │
    │       ▼
    │   ConfigManager.get_devices_for_current_time()
    │       │
    │       ▼
    │   Ejecutar solo devices que matchean
    │
    ▼
  Exit silencioso
```

## Base de Datos

### Tabla `settings`
```sql
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
```

### Tabla `users`
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT,
    role TEXT,
    email TEXT,
    permissions TEXT,  -- JSON array
    created_at TIMESTAMP,
    last_login TIMESTAMP
);
```

### Tabla `roles`
```sql
CREATE TABLE roles (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE,
    emoji TEXT,
    description TEXT,
    permissions TEXT,  -- JSON array
    is_system BOOLEAN
);
```

## Seguridad

- **Passwords**: Bcrypt hashing
- **Sessions**: Flask-Session con secreto
- **RBAC**: Permisos chequeados en cada request
- **API Tokens**: Bearer tokens para automatización
- **Rate Limiting**: Cooldown en endpoints sensibles
