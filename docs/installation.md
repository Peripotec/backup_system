# Instalación y Despliegue

Guía completa para instalar el Backup System en un servidor Linux.

## Requisitos

### Hardware
- CPU: 2+ cores
- RAM: 4 GB mínimo
- Disco: 50 GB+ (según cantidad de backups)

### Software
- Ubuntu 20.04+ / Debian 11+
- Python 3.8+
- Git
- TFTP server
- FTP server (para ZTE OLT)

## Instalación Rápida

```bash
# 1. Instalar dependencias del sistema
apt update
apt install -y python3 python3-pip python3-venv git tftpd-hpa

# 2. Clonar repositorio
cd /opt
git clone https://github.com/Peripotec/backup_system.git
cd backup_system

# 3. Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# 4. Instalar dependencias Python
pip install -r requirements.txt

# 5. Inicializar base de datos
python3 -c "from core.config_manager import get_config_manager; get_config_manager()"

# 6. Crear usuario admin
python3 create_admin.py

# 7. Configurar servicios systemd
cp backup-web.service /etc/systemd/system/
cp backup-cron.service /etc/systemd/system/
cp backup-cron.timer /etc/systemd/system/

# 8. Habilitar e iniciar servicios
systemctl daemon-reload
systemctl enable --now backup-web
systemctl enable --now backup-cron.timer

# 9. Verificar
systemctl status backup-web
curl http://localhost:5000
```

## Configuración de TFTP

### Instalar tftpd-hpa
```bash
apt install tftpd-hpa
```

### Configurar `/etc/default/tftpd-hpa`
```ini
TFTP_USERNAME="tftp"
TFTP_DIRECTORY="/var/lib/tftpboot"
TFTP_ADDRESS=":69"
TFTP_OPTIONS="--secure --create"
```

### Crear directorio y permisos
```bash
mkdir -p /var/lib/tftpboot
chown tftp:tftp /var/lib/tftpboot
chmod 777 /var/lib/tftpboot
```

### Reiniciar servicio
```bash
systemctl restart tftpd-hpa
```

## Configuración de FTP (para ZTE)

### Instalar vsftpd
```bash
apt install vsftpd
```

### Configurar `/etc/vsftpd.conf`
```ini
listen=YES
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
chroot_local_user=YES
allow_writeable_chroot=YES
```

### Crear usuario FTP
```bash
useradd -m -s /bin/false ftpbackup
passwd ftpbackup
```

## Servicios Systemd

### backup-web.service
Servicio web Flask.

```ini
[Unit]
Description=Backup System Web
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/backup_system
Environment="PATH=/opt/backup_system/venv/bin"
ExecStart=/opt/backup_system/venv/bin/python web_app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### backup-cron.timer
Timer para backups programados.

```ini
[Unit]
Description=Backup System Timer

[Timer]
OnCalendar=*:*:00
Persistent=false

[Install]
WantedBy=timers.target
```

## Estructura de Directorios

```
/opt/backup_system/
├── web_app.py           # Aplicación principal
├── backup_system.db     # Base de datos SQLite
├── inventory.yaml       # Inventario de dispositivos
├── core/                # Módulos core
├── vendors/             # Implementaciones por vendor
├── templates/           # Templates HTML
├── static/              # Assets estáticos
├── docs/                # Documentación
├── backups/             # Archivos de backup
│   ├── SW-CORE-01/
│   ├── SW-ACC-01/
│   └── .git/            # Versionado Git
└── logs/                # Logs del sistema
```

## Firewall

Puertos a abrir:

| Puerto | Protocolo | Uso |
|--------|-----------|-----|
| 5000 | TCP | Web UI |
| 69 | UDP | TFTP |
| 21 | TCP | FTP (ZTE) |
| 22 | TCP | SSH (saliente a equipos) |

```bash
ufw allow 5000/tcp
ufw allow 69/udp
ufw allow 21/tcp
```

## Nginx Reverse Proxy (Producción)

```nginx
server {
    listen 80;
    server_name backup.example.com;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## SSL con Certbot

```bash
apt install certbot python3-certbot-nginx
certbot --nginx -d backup.example.com
```

## Actualización

```bash
cd /opt/backup_system
git pull origin main
pip install -r requirements.txt
systemctl restart backup-web
```

## Backup de la Base de Datos

```bash
# Backup
cp /opt/backup_system/backup_system.db /backup/backup_system_$(date +%Y%m%d).db

# Restore
cp /backup/backup_system_20260101.db /opt/backup_system/backup_system.db
systemctl restart backup-web
```

## Logs

### Ver logs del servicio web
```bash
journalctl -u backup-web -f
```

### Ver logs de backups programados
```bash
journalctl -u backup-cron.service -f
```

### Archivo de log
```bash
tail -f /opt/backup_system/logs/backup_system.log
```

## Troubleshooting

### Servicio no inicia
```bash
journalctl -u backup-web -n 50
# Ver errores de Python
```

### TFTP no recibe archivos
```bash
# Verificar servicio
systemctl status tftpd-hpa

# Ver logs
tail -f /var/log/syslog | grep tftp

# Probar localmente
tftp localhost
> put testfile
```

### Base de datos corrupta
```bash
# Backup actual
mv backup_system.db backup_system.db.bak

# Reiniciar (crea nueva DB)
systemctl restart backup-web

# Reimportar usuarios si es necesario
```
