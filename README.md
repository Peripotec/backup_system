# Network Backup System

Sistema de respaldo automatizado para equipos de red (Huawei, HP, ZTE OLT) con:
- 🚀 Ejecución concurrente (ThreadPool)
- 📚 Versionado híbrido (Git para texto, Archivo para binarios)
- 🗄️ Base de datos SQLite para trazabilidad
- 🌐 Dashboard Web (Flask) con Dark Mode
- 🔐 RBAC (Control de acceso basado en roles)
- 📧 Notificaciones por Email
- 🔑 Vault encriptado para credenciales

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
└── vendors/          # Plugins por vendor
```

## Documentación
- [DEPLOY.md](DEPLOY.md) - Guía completa de instalación
