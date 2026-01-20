# Network Backup System

Sistema de respaldo automatizado para equipos de red (Huawei, HP, ZTE OLT, Cisco) con:
- 🚀 Ejecución concurrente (ThreadPool)
- 📚 Versionado híbrido (Git para texto, Archivo para binarios)
- 🗄️ Base de datos SQLite para trazabilidad
- 🌐 Dashboard Web (Flask) con Dark Mode
- 🔐 RBAC (Control de acceso basado en roles)
- 📧 Notificaciones por Email
- 🔑 Vault encriptado para credenciales
- 📋 **Sistema de Auditoría** (tipo Bookstack)
- ✅ **Control de dispositivos** (habilitar/deshabilitar con trazabilidad)

## Quick Start

```bash
# Clonar
git clone https://github.com/Peripotec/backup_system.git
cd backup_system

# Instalar
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configurar
nano settings.py      # SMTP, rutas
nano inventory.yaml   # Dispositivos

# Ejecutar
python3 main.py --dry-run  # Prueba
python3 main.py            # Producción
```

## Estructura
```
├── main.py           # CLI
├── settings.py       # Configuración
├── inventory.yaml    # Dispositivos
├── web_app.py        # Dashboard
├── core/             # Lógica central
│   ├── engine.py     # Motor de backup
│   ├── db_manager.py # SQLite (jobs, audit)
│   └── config_manager.py
├── vendors/          # Plugins por vendor
├── templates/        # HTML (Jinja2)
└── docs/             # Documentación
```

## Documentación

- [DEPLOY.md](DEPLOY.md) - Guía completa de instalación
- [docs/rbac.md](docs/rbac.md) - Control de acceso y roles
- [docs/audit.md](docs/audit.md) - Sistema de auditoría
- [docs/scheduling.md](docs/scheduling.md) - Programación de backups
- [docs/vendors.md](docs/vendors.md) - Plugins de vendors
- [docs/api-reference.md](docs/api-reference.md) - Referencia de API

