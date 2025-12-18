import os
from pathlib import Path

# =======================
# PATHS
# =======================
# Base directory for the backup execution
BASE_DIR = Path(__file__).resolve().parent

# Root directory for storing backups
# In Linux this should be /Backup or /opt/Backup as configured
BACKUP_ROOT_DIR = os.getenv("BACKUP_ROOT_DIR", "/Backup")

# Subdirectories
ARCHIVE_DIR = os.path.join(BACKUP_ROOT_DIR, "archive")
LATEST_DIR = os.path.join(BACKUP_ROOT_DIR, "latest")
REPO_DIR = os.path.join(BACKUP_ROOT_DIR, "repo")  # For Git

# Inventory File
INVENTORY_FILE = os.path.join(BASE_DIR, "inventory.yaml")

# Database File
DB_FILE = os.path.join(BASE_DIR, "backups.db")

# Log Directory
LOG_DIR = os.getenv("LOG_DIR", "/var/log/backup_system")

# =======================
# CONCURRENCY
# =======================
# Number of simultaneous backups
MAX_WORKERS = 10

# =======================
# RETENTION
# =======================
# Days to keep archive files (binary)
RETENTION_DAYS = 90

# =======================
# NOTIFICATIONS (SMTP)
# =======================
SMTP_ENABLED = True
SMTP_SERVER = "smtp.gmail.com"  # Placeholder
SMTP_PORT = 587
SMTP_USER = "alertas@tu-empresa.com"
SMTP_PASS = "tu_password_aqui"
SMTP_FROM = "Backup System <alertas@tu-empresa.com>"
SMTP_TO = ["admin@tu-empresa.com"]

# =======================
# EXTRAS
# =======================
# TFTP/FTP Server IP (The machine running this script)
SERVER_IP = "200.2.124.167"

# TFTP/FTP Credentials/Paths for staging check
# These are used to verify if the device actually uploaded the file
TFTP_ROOT = "/var/lib/tftpboot"
FTP_ROOT = "/home/ftpusuarios"
