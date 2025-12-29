import argparse
import sys
from core.engine import BackupEngine
from core.logger import log

from settings import RETENTION_DAYS

def main():
    parser = argparse.ArgumentParser(description="Scalable Network Backup System")
    parser.add_argument("--group", help="Run backup only for a specific group")
    parser.add_argument("--device", help="Run backup only for a specific device (sysname or hostname)")
    parser.add_argument("--dry-run", action="store_true", help="Simulate backup without connecting to devices")
    parser.add_argument("--test-email", action="store_true", help="Send a test email and exit")
    
    args = parser.parse_args()

    # Special Test Mode
    if args.test_email:
        from core.notifier import Notifier
        notifier = Notifier()
        log.info("Sending test email...")
        notifier.send_summary(1, 1, 0, {}, {"TestDevice": "This is a test diff"}, 0.1)
        sys.exit(0)

    # Normal Execution
    engine = BackupEngine(dry_run=args.dry_run)
    
    if args.group:
        log.info(f"Targeting specific group: {args.group}")
    if args.device:
        log.info(f"Targeting specific device: {args.device}")
    
    engine.run(target_group=args.group, target_device=args.device)
    
    # Cleanup only on full runs or generic maintenance
    if not args.group and not args.device:
        engine.cleanup_old_backups(RETENTION_DAYS)

if __name__ == "__main__":
    main()
