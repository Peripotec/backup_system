# Backup System - Documentación

Sistema de backup automatizado para dispositivos de red con soporte multi-vendor.

## 📚 Índice

| Documento | Descripción |
|-----------|-------------|
| [Arquitectura](architecture.md) | Arquitectura general del sistema |
| [Inventory Providers](inventory-providers.md) | Guía de proveedores de inventario |
| [Integración NetBox](netbox-integration.md) | Cómo integrar con NetBox |
| [Scheduling](scheduling.md) | Sistema de programación de backups |
| [RBAC](rbac.md) | Control de acceso basado en roles |
| [API Reference](api-reference.md) | Documentación de la API REST |

## 🚀 Quick Start

```bash
# 1. Clonar repositorio
git clone https://github.com/Peripotec/backup_system.git
cd backup_system

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Iniciar servicio web
python web_app.py

# 4. Acceder a la UI
# http://localhost:5000
```

## 📁 Estructura del Proyecto

```
backup_system/
├── core/
│   ├── config_manager.py    # Gestión de configuración (DB)
│   ├── engine.py            # Motor de backups
│   ├── inventory_provider.py # Abstracción de inventario
│   ├── models.py            # Modelos de datos (Device)
│   └── notifier.py          # Notificaciones por email
├── vendors/
│   ├── base.py             # Clase base para vendors
│   ├── huawei.py           # Implementación Huawei
│   ├── cisco.py            # Implementación Cisco
│   ├── hp.py               # Implementación HP
│   └── zte_olt.py          # Implementación ZTE OLT
├── templates/              # Templates HTML (Jinja2)
├── static/                 # Assets estáticos
├── docs/                   # Esta documentación
├── inventory.yaml          # Inventario de dispositivos
├── web_app.py              # Aplicación Flask
└── scheduled_runner.py     # Runner para systemd timer
```

## 🔧 Configuración

La configuración se almacena en SQLite y se gestiona desde:
- **UI**: Configuración → Backup / Email
- **API**: `GET/PUT /api/settings`

### Variables Principales

| Setting | Descripción | Default |
|---------|-------------|---------|
| `backup_enabled` | Habilitar backups | `true` |
| `global_schedule` | Horario por defecto | `02:00` |
| `inventory_source` | Fuente de inventario | `yaml` |
| `tftp_server` | IP del servidor TFTP | `127.0.0.1` |

## 📞 Soporte

- **Repositorio**: https://github.com/Peripotec/backup_system
- **Issues**: https://github.com/Peripotec/backup_system/issues
