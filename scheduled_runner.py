#!/usr/bin/env python3
"""
Scheduled Backup Runner - Enterprise Edition
=============================================
Este script es invocado por systemd timer cada minuto.
Implementa early-exit inteligente basado en la configuración de DB.

Estrategia:
- Timer frecuente (cada minuto) + early-exit
- Más flexible que regenerar OnCalendar dinámicamente
- Permite cambios inmediatos desde la web sin daemon-reload
- Locking con archivo para evitar ejecuciones simultáneas
- Envía actualizaciones a la UI web via HTTP

Autor: Backup System Enterprise
"""

import os
import sys
import fcntl
from datetime import datetime

# Agregar path del proyecto
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config_manager import get_config_manager
from core.engine import BackupEngine
from core.logger import log
from core.remote_ui_notifier import RemoteUINotifier, create_remote_status_callback

LOCK_FILE = '/tmp/backup_system.lock'


def acquire_lock():
    """
    Adquirir lock exclusivo para evitar ejecuciones simultáneas.
    Returns file handle if acquired, None if already locked.
    """
    try:
        lock_fd = open(LOCK_FILE, 'w')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return lock_fd
    except (IOError, OSError):
        return None


def release_lock(lock_fd):
    """Release lock file."""
    if lock_fd:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()


def main():
    """
    Main entry point para ejecución programada.
    - Verifica si el horario actual corresponde según la DB
    - Si no corresponde, hace early-exit silencioso
    - Si corresponde, ejecuta backup con filtro de devices
    - Envía actualizaciones a la UI web
    """
    current_time = datetime.now().strftime('%H:%M')
    log.info(f"=== Scheduled Runner iniciado ({current_time}) ===")
    
    # 1. Verificar lock
    lock_fd = acquire_lock()
    if not lock_fd:
        log.warning("Otra instancia ya está corriendo. Saliendo.")
        sys.exit(0)
    
    try:
        # 2. Consultar ConfigManager
        config = get_config_manager()
        should_run, reason = config.should_run_backup_now(current_time)
        
        if not should_run:
            log.debug(f"Early-exit: {reason}")
            sys.exit(0)
        
        log.info(f"Iniciando backup programado: {reason}")
        
        # 3. Crear notificador remoto para UI
        remote_notifier = RemoteUINotifier(current_time)
        
        # 4. Ejecutar engine con filtro de horario
        engine = BackupEngine()
        
        # Conectar callback para actualizaciones de UI
        engine.status_callback = create_remote_status_callback(remote_notifier)
        
        # Contar dispositivos antes de iniciar
        total_devices = 0
        if 'groups' in engine.inventory:
            for group in engine.inventory['groups']:
                for device in group.get('devices', []):
                    if device.get('enabled', True):
                        total_devices += 1
        
        # Notificar inicio a la UI
        remote_notifier.notify_start(total_devices)
        
        # Ejecutar backup
        engine.run_scheduled(current_time)
        
        # Notificar fin a la UI
        remote_notifier.notify_end()
        
        log.info("=== Scheduled Runner finalizado ===")
        
    except Exception as e:
        log.error(f"Error en scheduled runner: {e}")
        sys.exit(1)
    finally:
        release_lock(lock_fd)


if __name__ == '__main__':
    main()
