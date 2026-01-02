# Sistema de Scheduling

El sistema de backups usa un modelo de herencia jerárquica para determinar cuándo ejecutar
cada dispositivo.

## Arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                    systemd timer (cada minuto)                   │
│                          backup-cron.timer                       │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                      scheduled_runner.py                         │
│                                                                  │
│   1. ¿backup_enabled?  → No → Exit                              │
│   2. ¿Hay schedule para HH:MM actual?  → No → Exit              │
│   3. Adquirir lock                                               │
│   4. BackupEngine.run_scheduled(current_time)                   │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│               ConfigManager.get_devices_for_current_time()       │
│                                                                  │
│   Para cada device:                                              │
│     schedule = get_effective_schedule(device)                   │
│     if current_time in schedule → incluir device                │
└─────────────────────────────────────────────────────────────────┘
```

## Jerarquía de Herencia

```
Device Schedule (más específico)
    ↓
Model Schedule (schedule_model_<vendor>_<modelo>)
    ↓
Vendor Schedule (schedule_vendor_<vendor>)
    ↓
Global Schedule (global_schedule) (más general)
```

**Reglas:**
- El primer nivel que tenga un schedule definido gana
- Schedule vacío = heredar del nivel superior
- Un device solo se ejecuta UNA vez por tick (no se duplica)

## Configuración de Schedules

### Global Schedule
Aplica a todos los dispositivos que no tengan schedule específico.

```
Setting: global_schedule
Valor: "02:00, 14:00"
```

### Vendor Schedule
Aplica a todos los dispositivos de un vendor específico.

```
Setting: schedule_vendor_huawei
Valor: "03:00"

Setting: schedule_vendor_cisco
Valor: "04:00"
```

### Model Schedule (P2)
Aplica a todos los dispositivos de un modelo específico.

```
Setting: schedule_model_huawei_s5720
Valor: "05:00"
```

### Device Schedule
Se define en el inventario directamente:

```yaml
devices:
  - sysname: "SW-CRITICO-01"
    ip: "192.168.1.1"
    schedule: "01:00, 07:00, 13:00, 19:00"  # 4 veces al día
```

## Formato de Horarios

- Formato: `HH:MM` (24 horas)
- Múltiples horarios: separados por coma
- Ejemplos válidos:
  - `02:00`
  - `02:00, 14:00`
  - `00:00, 06:00, 12:00, 18:00`

## Validaciones

1. **Formato HH:MM**: Regex `^\d{2}:\d{2}$`
2. **Horas válidas**: 00-23
3. **Minutos válidos**: 00-59
4. **Deduplicación**: Se eliminan horarios duplicados
5. **Ordenamiento**: Se ordenan cronológicamente

## Timer de Systemd

### backup-cron.timer
```ini
[Unit]
Description=Backup System Timer

[Timer]
OnCalendar=*:*:00
Persistent=false

[Install]
WantedBy=timers.target
```

### backup-cron.service
```ini
[Unit]
Description=Backup System Runner

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/backup_system/scheduled_runner.py
WorkingDirectory=/opt/backup_system
```

## Logging

Cuando se ejecuta un backup programado, se loguea:

```
Tick 02:00: 15 devices (3 por device, 2 por model, 5 por vendor, 5 por global)
```

Esto muestra cuántos dispositivos se ejecutaron por cada nivel de herencia.

## Early Exit

Para evitar carga innecesaria, el runner sale silenciosamente si:
1. `backup_enabled = false`
2. No hay ningún schedule que coincida con el minuto actual

## Locking

El runner usa un archivo de lock (`/tmp/backup_system.lock`) para evitar
ejecuciones concurrentes si el timer se dispara mientras aún está corriendo.

## Troubleshooting

### Ver próximas ejecuciones
```bash
# Ver timer status
systemctl list-timers | grep backup
```

### Forzar ejecución manual
```bash
python3 /opt/backup_system/scheduled_runner.py
```

### Ver logs
```bash
journalctl -u backup-cron.service -f
```

### Verificar schedule de un device
```python
from core.config_manager import get_config_manager
cfg = get_config_manager()
device = {'sysname': 'SW-01', 'vendor': 'Huawei', 'modelo': 'S5720'}
schedule, source = cfg.get_effective_schedule(device)
print(f"Schedule: {schedule}, Source: {source}")
```
