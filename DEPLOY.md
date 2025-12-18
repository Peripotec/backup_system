# Deployment Guide

## Prerequisites
```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip git
```

## Installation from GitHub

```bash
# 1. Clone repository
cd /opt
sudo git clone https://github.com/Peripotec/backup_system.git
sudo chown -R $USER:$USER backup_system
cd backup_system

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Create backup directories
sudo mkdir -p /Backup/archive /Backup/latest /Backup/repo
sudo chown -R $USER:$USER /Backup

# 4. Initialize Git repo for versioning
cd /Backup/repo
git init
git config user.name "Backup System"
git config user.email "backup@localhost"
cd /opt/backup_system
```

## Configuration

```bash
# Edit settings
nano settings.py   # SMTP credentials, SERVER_IP

# Edit inventory
nano inventory.yaml  # Add your devices
```

## Web Dashboard Service

```bash
# Install service
sudo cp backup-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable backup-web
sudo systemctl start backup-web

# Check status
sudo systemctl status backup-web

# Access: http://SERVER_IP:5000
```

## Cron Setup

```bash
sudo crontab -e
```

Add:
```cron
# Daily backup at 3 AM
0 3 * * * /opt/backup_system/venv/bin/python3 /opt/backup_system/main.py >> /var/log/backup_system.log 2>&1
```

## Updates from GitHub

```bash
cd /opt/backup_system
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart backup-web
```

## Testing

```bash
# Dry run (no real connections)
python3 main.py --dry-run

# Test email
python3 main.py --test-email

# Real backup
python3 main.py
```
