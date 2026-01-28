import yaml
import time
import os
import shutil
import socket
from datetime import datetime
import importlib
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from settings import INVENTORY_FILE, MAX_WORKERS, ARCHIVE_DIR, TFTP_ROOT
from core.logger import log
from core.db_manager import DBManager
from core.git_manager import GitManager
from core.notifier import Notifier
from core.vault import get_credentials_for_device
from core.config_manager import get_config_manager
from core.run_logger import RunLogger
from core.circuit_breaker import get_circuit_breaker

# Vendors that use global locks (TFTP file contention)
# These should NOT compete for pool slots - processed sequentially after parallel batch
SEQUENTIAL_VENDORS = {'hp', 'zte_olt'}

class BackupEngine:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.db = DBManager()
        self.git = GitManager()
        self.notifier = Notifier()
        self.inventory = self._load_inventory()
        self.status_callback = None  # Optional callback for web UI updates
        self.circuit_breaker = get_circuit_breaker()  # Circuit breaker for group failures
        
        # Cleanup stale IN_PROGRESS jobs from previous crashed runs
        self.db.cleanup_stale_jobs(max_age_minutes=30)

    def _load_inventory(self):
        """Load inventory with validation, auto-backup, and fallback."""
        backup_file = f"{INVENTORY_FILE}.bak"
        try:
            with open(INVENTORY_FILE, 'r') as f:
                data = yaml.safe_load(f)
            
            # Validate structure
            if not data or 'groups' not in data:
                raise ValueError("Invalid inventory: missing 'groups' key")
            
            # Auto-backup on successful load
            shutil.copy2(INVENTORY_FILE, backup_file)
            log.debug(f"Inventory backup created: {backup_file}")
            
            return data
        except FileNotFoundError:
            # Try to restore from backup
            if os.path.exists(backup_file):
                log.warning(f"Inventory not found, restoring from backup")
                shutil.copy2(backup_file, INVENTORY_FILE)
                return self._load_inventory()
            log.error("No inventory file found")
            return {'groups': []}
        except Exception as e:
            # If corrupted, try backup
            if os.path.exists(backup_file):
                log.warning(f"Inventory corrupted ({e}), loading backup")
                with open(backup_file, 'r') as f:
                    return yaml.safe_load(f)
            log.error(f"Failed to load inventory: {e}")
            return {'groups': []}

    def _get_vendor_plugin(self, vendor_name):
        """
        Dynamically imports the vendor class from vendors/<vendor_name>.py
        Expected class name: Title Case of vendor_name (e.g. 'huawei' -> 'Huawei', 'zte_olt' -> 'ZteOlt')
        """
        try:
            module_name = f"vendors.{vendor_name}"
            # Clean class name logic: zte_olt -> ZteOlt, huawei -> Huawei
            class_name = "".join(x.title() for x in vendor_name.split('_'))
            
            module = importlib.import_module(module_name)
            return getattr(module, class_name)
        except ImportError:
            log.error(f"Vendor plugin {vendor_name} not found.")
            return None
        except AttributeError:
            log.error(f"Class {class_name} not found in {vendor_name} plugin.")
            return None

    def _preflight_checks(self):
        """
        Run pre-flight checks before starting a batch backup.
        Returns a list of issues found (empty = all OK).
        """
        issues = []
        config = get_config_manager()
        
        # 1. TFTP Server reachable (UDP port 69)
        tftp_server = config.get_setting('tftp_server')
        if tftp_server and tftp_server not in ('127.0.0.1', 'localhost', '::1'):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                # Just try to connect - TFTP uses UDP so this won't establish a real connection
                sock.connect((tftp_server, 69))
                sock.close()
                log.debug(f"TFTP server {tftp_server} is reachable")
            except socket.timeout:
                issues.append(f"TFTP server {tftp_server} timeout")
            except Exception as e:
                issues.append(f"TFTP server {tftp_server} unreachable: {e}")
        
        # 2. Disk space check (minimum 5GB free on archive)
        if os.path.exists(ARCHIVE_DIR):
            try:
                usage = shutil.disk_usage(ARCHIVE_DIR)
                free_gb = usage.free / (1024**3)
                if free_gb < 5:
                    issues.append(f"Low disk space: {free_gb:.1f}GB free (minimum 5GB recommended)")
                else:
                    log.debug(f"Disk space OK: {free_gb:.1f}GB free")
            except Exception as e:
                issues.append(f"Cannot check disk space: {e}")
        
        # 3. TFTP directory writable
        if os.path.exists(TFTP_ROOT):
            test_file = os.path.join(TFTP_ROOT, '.write_test')
            try:
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
                log.debug(f"TFTP root {TFTP_ROOT} is writable")
            except Exception as e:
                issues.append(f"TFTP root not writable: {e}")
        
        return issues

    def process_device(self, device, group_name="Default", vendor_type="generic", credential_ids=None):
        """
        Worker function to process a single device.
        """
        # PRIMARY ID: sysname (fallback to hostname for legacy)
        sysname = device.get('sysname') or device.get('hostname')
        
        # CONNECTION HOST: hostname (can be IP or DNS name)
        # Note: 'hostname' is used by plugins for connection headers/filenames usually
        # We ensure it's available.
        
        start_time = time.time()
        
        # Check circuit breaker - skip if group is paused due to failures
        if self.circuit_breaker.is_open(group_name):
            log.warning(f"Skipping {sysname}: circuit open for group '{group_name}'")
            if self.status_callback:
                self.status_callback(sysname, "skipped", f"Grupo {group_name} pausado por fallas")
            return {"status": "SKIPPED", "hostname": sysname, "error": "Circuit breaker open"}
        
        # Metadata logging
        criticidad = device.get('criticidad', 'N/A')
        log.info(f"Starting backup for {sysname} ({vendor_type}) [Crit:{criticidad}]")
        
        # Notify UI that we're starting this device
        if self.status_callback:
            self.status_callback(sysname, "start")
        
        if self.dry_run:
            time.sleep(0.5) # Simulate work
            log.info(f"[DRY-RUN] Backup simulated for {sysname}")
            self.db.record_job(sysname, vendor_type, group_name, "SUCCESS", "Dry Run", duration=0.5)
            if self.status_callback:
                self.status_callback(sysname, "success", "Dry Run")
            return {"status": "SUCCESS", "hostname": sysname, "diff": None}

        # Real Execution
        try:
            VendorClass = self._get_vendor_plugin(vendor_type)
            if not VendorClass:
                raise ValueError(f"Unknown vendor: {vendor_type}")
            
            # Get credentials from vault if credential_ids provided
            credentials = []
            if credential_ids:
                credentials = get_credentials_for_device(sysname, credential_ids)
                log.debug(f"Loaded {len(credentials)} credentials from vault for {sysname}")
            
            # Prepare device info for plugin
            # Ensure plugin receives the correct 'hostname' for file naming preference
            # If we want files named by sysname, pass sysname as hostname to plugin
            plugin_device_info = device.copy()
            plugin_device_info['hostname'] = sysname 
            
            plugin = VendorClass(plugin_device_info, self.db, self.git, credentials)
            
            # Connect debug log callback to plugin
            if self.status_callback:
                def plugin_log(msg):
                    self.status_callback(sysname, "debug", msg)
                plugin.log_callback = plugin_log
            
            archive_path, size, changed = plugin.backup()
            
            # Log saving
            if self.status_callback:
                self.status_callback(sysname, "saving")
            
            duration = time.time() - start_time
            msg = f"{size} bytes"
            if changed:
                msg += " (cambios)"
                if self.status_callback:
                    self.status_callback(sysname, "git")
                diff = self.git.get_diff(plugin.hostname + ".cfg")
            else:
                diff = None

            self.db.record_job(
                sysname, vendor_type, group_name, "SUCCESS", msg, 
                file_path=archive_path, file_size=size, duration=duration, changed=changed
            )
            
            log.info(f"Success: {sysname} ({size} bytes)")
            
            # Notify UI of success
            if self.status_callback:
                self.status_callback(sysname, "success", msg)
            
            # Record success in circuit breaker
            self.circuit_breaker.record_success(group_name)
            
            return {"status": "SUCCESS", "hostname": sysname, "diff": diff}

        except Exception as e:
            duration = time.time() - start_time
            log.error(f"Error backup {sysname}: {e}")
            self.db.record_job(
                sysname, vendor_type, group_name, "ERROR", str(e), 
                duration=duration
            )
            
            # Notify UI of error
            if self.status_callback:
                self.status_callback(sysname, "error", str(e))
            
            # Record failure in circuit breaker
            self.circuit_breaker.record_failure(group_name, str(e))
            
            # Audit event for device error
            self.db.log_audit_event(
                user_id=None,
                username="SYSTEM",
                event_type="BACKUP_DEVICE_ERROR",
                event_category="BACKUP",
                entity_type="device",
                entity_id=sysname,
                entity_name=sysname,
                details={
                    "vendor": vendor_type,
                    "group": group_name,
                    "error": str(e)[:500],  # Truncate long errors
                    "duration_seconds": round(duration, 1)
                }
            )
            
            return {"status": "ERROR", "hostname": sysname, "error": str(e)}


    def cleanup_old_backups(self):
        """Delete backups older than N days. Reads config from DB."""
        config = get_config_manager()
        
        # Check if cleanup is enabled
        cleanup_enabled = config.get_setting('cleanup_enabled')
        if cleanup_enabled != 'true':
            log.info("Cleanup disabled in settings. Skipping.")
            return
        
        # Get retention days from config (with guardrails)
        try:
            retention_days = int(config.get_setting('archive_retention_days') or 90)
        except (ValueError, TypeError):
            retention_days = 90
        
        # Guardrail: minimum 7 days to prevent accidental deletion
        if retention_days < 7:
            log.warning(f"Retention days {retention_days} too low. Using minimum of 7.")
            retention_days = 7
        
        log.info(f"Starting cleanup: deleting files older than {retention_days} days...")
        
        # 1. DB Cleanup
        self.db.delete_old_jobs(retention_days)
        
        # 2. File Cleanup
        limit = time.time() - (retention_days * 86400)
        count = 0
        
        if not os.path.exists(ARCHIVE_DIR):
            log.warning(f"Archive directory does not exist: {ARCHIVE_DIR}")
            return
        
        # Walk ARCHIVE_DIR
        for root, dirs, files in os.walk(ARCHIVE_DIR):
            for f in files:
                path = os.path.join(root, f)
                try:
                    mtime = os.path.getmtime(path)
                    if mtime < limit:
                        os.remove(path)
                        log.debug(f"Deleted: {path}")
                        count += 1
                except Exception as e:
                    log.error(f"Error cleaning {path}: {e}")
        
        log.info(f"Cleanup finished. Deleted {count} files.")

    def run(self, target_group=None, target_devices=None):
        """
        Main runner. Spawns threads.
        target_group: filter by group name
        target_devices: list of device hostnames or sysnames to process
        """
        log.info(f"Starting Backup Run (Dry Run={self.dry_run})")
        
        # Run preflight checks
        preflight_issues = self._preflight_checks()
        if preflight_issues:
            for issue in preflight_issues:
                log.warning(f"Preflight check: {issue}")
            # Continue anyway but log warnings - could be made configurable to abort
        
        run_id = self.db.start_run(run_type="MANUAL")
        
        # Create run logger for this execution
        run_logger = RunLogger(run_id, run_type="MANUAL")
        start_time = time.time()
        
        # Log audit event for run start
        self.db.log_audit_event(
            user_id=None,
            username="SYSTEM",
            event_type="BACKUP_RUN_START",
            event_category="BACKUP",
            entity_type="run",
            entity_id=str(run_id),
            details={"type": "MANUAL", "dry_run": self.dry_run}
        )
        
        # Convert single device to list for backward compatibility
        if target_devices and not isinstance(target_devices, list):
            target_devices = [target_devices]
        
        # Separate devices into parallel (no lock) and sequential (with lock) batches
        parallel_devices = []   # Vendors without global lock - safe to parallelize
        sequential_devices = [] # Vendors with global lock (HP, ZTE OLT) - run one at a time
        disabled_devices = []   # Track disabled devices for report
        
        if 'groups' not in self.inventory:
            log.warning("No groups found in inventory.")
            return

        for group in self.inventory['groups']:
            grp_name = group['name']
            grp_vendor = group['vendor']  # May be empty for mixed groups
            grp_credential_ids = group.get('credential_ids', [])

            if target_group and target_group != grp_name:
                continue

            for device in group['devices']:
                # Skip disabled devices but collect for report
                if device.get('enabled') is False:
                    sysname = device.get('sysname') or device.get('hostname')
                    log.info(f"Skipping disabled device: {sysname} (reason: {device.get('disabled_reason', 'N/A')})")
                    if not target_devices or sysname in target_devices or device.get('hostname') in (target_devices or []):
                        disabled_dev = device.copy()
                        disabled_dev['_group_name'] = grp_name
                        disabled_devices.append(disabled_dev)
                    continue
                
                # Filter by specific devices list
                if target_devices:
                    sysname = device.get('sysname')
                    hostname = device.get('hostname')
                    if sysname not in target_devices and hostname not in target_devices:
                        continue
                
                # Determine vendor
                vendor_type = device.get('vendor') or grp_vendor
                if not vendor_type:
                    log.warning(f"Skipping device {device.get('sysname', device.get('hostname'))}: no vendor defined")
                    continue
                
                # Build credential list
                device_cred_ids = device.get('credential_ids', [])
                if device_cred_ids:
                    all_cred_ids = list(device_cred_ids)
                    for grp_cred in grp_credential_ids:
                        if grp_cred not in all_cred_ids:
                            all_cred_ids.append(grp_cred)
                    device_cred_ids = all_cred_ids
                else:
                    device_cred_ids = grp_credential_ids
                
                # Package device info for later processing
                device_task = {
                    'device': device,
                    'group_name': grp_name,
                    'vendor_type': vendor_type,
                    'cred_ids': device_cred_ids
                }
                
                # Sort into parallel or sequential batch based on vendor
                if vendor_type.lower() in SEQUENTIAL_VENDORS:
                    sequential_devices.append(device_task)
                else:
                    parallel_devices.append(device_task)
        
        total_devices = len(parallel_devices) + len(sequential_devices)
        
        # Log start with total device count
        run_logger.start(total_devices)
        
        if sequential_devices:
            log.info(f"Smart concurrency: {len(parallel_devices)} parallel, {len(sequential_devices)} sequential (HP/ZTE)")
        
        # Phase 1: Execute parallel devices (no lock contention)
        parallel_futures = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for task in parallel_devices:
                future = executor.submit(
                    self.process_device, 
                    task['device'], 
                    task['group_name'], 
                    task['vendor_type'],
                    task['cred_ids']
                )
                parallel_futures.append(future)

        # Collect parallel results
        results = []
        for future in concurrent.futures.as_completed(parallel_futures):
            result = future.result()
            results.append(result)
            
            # Log each result to run log
            if result['status'] == 'SUCCESS':
                run_logger.log_success(
                    result['hostname'],
                    size=0,
                    changed=bool(result.get('diff'))
                )
            else:
                run_logger.log_error(
                    result['hostname'],
                    result.get('error', 'Unknown error')
                )
        
        # Phase 2: Execute sequential devices one at a time (vendors with global lock)
        if sequential_devices:
            log.info(f"Starting sequential phase: {len(sequential_devices)} devices (HP/ZTE)")
            for task in sequential_devices:
                sysname = task['device'].get('sysname') or task['device'].get('hostname')
                log.info(f"Processing sequential device: {sysname}")
                
                result = self.process_device(
                    task['device'],
                    task['group_name'],
                    task['vendor_type'],
                    task['cred_ids']
                )
                results.append(result)
                
                # Log result
                if result['status'] == 'SUCCESS':
                    run_logger.log_success(
                        result['hostname'],
                        size=0,
                        changed=bool(result.get('diff'))
                    )
                else:
                    run_logger.log_error(
                        result['hostname'],
                        result.get('error', 'Unknown error')
                    )

        # Success/Stats
        total = len(results)
        success = sum(1 for r in results if r['status'] == "SUCCESS")
        errors = total - success
        
        failed_hosts = {r['hostname']: r.get('error', 'Unknown') for r in results if r['status'] == "ERROR"}
        diff_summary = {r['hostname']: r['diff'] for r in results if r.get('diff')}

        # Calculate duration
        duration = time.time() - start_time
        
        # End run logger
        run_logger.end(success, errors, duration)
        
        # Update run record with log path
        self.db.end_run(run_id, total, success, errors, log_path=run_logger.get_log_path())
        run_logger.close()
        
        # Log audit event for run end
        self.db.log_audit_event(
            user_id=None,
            username="SYSTEM",
            event_type="BACKUP_RUN_END",
            event_category="BACKUP",
            entity_type="run",
            entity_id=str(run_id),
            details={
                "type": "MANUAL",
                "total": total,
                "success": success,
                "errors": errors,
                "duration_seconds": round(duration, 1),
                "log_path": run_logger.get_log_path()
            }
        )
        
        # Notify with disabled devices
        self.notifier.send_summary(total, success, errors, failed_hosts, diff_summary, duration, disabled_devices)
        
        log.info(f"Run Completed. Success: {success}, Errors: {errors}")

    def run_scheduled(self, current_time_hhmm):
        """
        Run backup for devices whose schedule matches the current time.
        Uses ConfigManager's schedule inheritance:
        device -> model -> vendor -> global
        
        Args:
            current_time_hhmm: Current time as HH:MM string
        """
        log.info(f"=== Ejecución Programada ({current_time_hhmm}) ===")
        
        # Run preflight checks
        preflight_issues = self._preflight_checks()
        if preflight_issues:
            for issue in preflight_issues:
                log.warning(f"Preflight check: {issue}")
            # Continue anyway but log warnings
        
        run_id = self.db.start_run(run_type="CRON", triggered_by=f"CRON:{current_time_hhmm}")
        
        # Create run logger for this execution
        run_logger = RunLogger(run_id, run_type="CRON")
        start_time = time.time()
        
        # Log audit event for run start
        self.db.log_audit_event(
            user_id=None,
            username="SYSTEM",
            event_type="BACKUP_RUN_START",
            event_category="BACKUP",
            entity_type="run",
            entity_id=str(run_id),
            details={"type": "CRON", "schedule": current_time_hhmm}
        )
        
        # Collect all devices with their vendor info
        all_devices = []
        disabled_devices = []  # Track disabled devices for report
        if 'groups' not in self.inventory:
            log.warning("No groups found in inventory.")
            return
        
        for group in self.inventory['groups']:
            grp_vendor = group['vendor']
            grp_credential_ids = group.get('credential_ids', [])
            
            for device in group['devices']:
                # Skip disabled devices but collect for report
                if device.get('enabled') is False:
                    sysname = device.get('sysname') or device.get('hostname')
                    log.debug(f"Skipping disabled device from schedule: {sysname}")
                    # Add to disabled list with group info for report
                    disabled_dev = device.copy()
                    disabled_dev['_group_name'] = group['name']
                    disabled_devices.append(disabled_dev)
                    continue
                
                # Enrich device with vendor and group info for schedule calculation
                enriched = device.copy()
                # Device vendor takes priority over group vendor (for mixed groups)
                enriched['vendor'] = device.get('vendor') or grp_vendor
                enriched['_group_name'] = group['name']
                enriched['_group_cred_ids'] = grp_credential_ids
                all_devices.append(enriched)
        
        # Filter devices by current schedule
        matching_devices = get_config_manager().get_devices_for_current_time(
            all_devices, 
            current_time_hhmm
        )
        
        if not matching_devices:
            log.info(f"No hay dispositivos programados para {current_time_hhmm}")
            run_logger.start(0)
            run_logger.log("No devices scheduled for this time")
            run_logger.end(0, 0, 0)
            self.db.end_run(run_id, 0, 0, 0, log_path=run_logger.get_log_path())
            run_logger.close()
            # Still send email if there are disabled devices
            if disabled_devices:
                self.notifier.send_summary(0, 0, 0, {}, {}, 0, disabled_devices)
            return
        
        log.info(f"Dispositivos a respaldar: {len(matching_devices)}")
        
        tasks = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for device in matching_devices:
                # Extract metadata we added
                grp_name = device.pop('_group_name')
                grp_credential_ids = device.pop('_group_cred_ids')
                vendor_type = device.get('vendor')
                
                # Credential handling (same logic as run())
                device_cred_ids = device.get('credential_ids', [])
                if device_cred_ids:
                    all_cred_ids = list(device_cred_ids)
                    for grp_cred in grp_credential_ids:
                        if grp_cred not in all_cred_ids:
                            all_cred_ids.append(grp_cred)
                    device_cred_ids = all_cred_ids
                else:
                    device_cred_ids = grp_credential_ids
                
                future = executor.submit(
                    self.process_device,
                    device,
                    grp_name,
                    vendor_type,
                    device_cred_ids
                )
                tasks.append(future)
        
        # Log start with device count
        run_logger.start(len(tasks))

        # Collect Results
        results = []
        for future in concurrent.futures.as_completed(tasks):
            result = future.result()
            results.append(result)
            
            # Log each result to run log
            if result['status'] == 'SUCCESS':
                run_logger.log_success(
                    result['hostname'],
                    size=0,
                    changed=bool(result.get('diff'))
                )
            else:
                run_logger.log_error(
                    result['hostname'],
                    result.get('error', 'Unknown error')
                )
        
        # Stats
        total = len(results)
        success = sum(1 for r in results if r['status'] == "SUCCESS")
        errors = total - success
        
        failed_hosts = {r['hostname']: r.get('error', 'Unknown') for r in results if r['status'] == "ERROR"}
        diff_summary = {r['hostname']: r['diff'] for r in results if r.get('diff')}
        
        # Calculate duration
        duration = time.time() - start_time
        
        # End run logger
        run_logger.end(success, errors, duration)
        
        # Update run record with log path
        self.db.end_run(run_id, total, success, errors, log_path=run_logger.get_log_path())
        run_logger.close()
        
        # Log audit event for run end
        self.db.log_audit_event(
            user_id=None,
            username="SYSTEM",
            event_type="BACKUP_RUN_END",
            event_category="BACKUP",
            entity_type="run",
            entity_id=str(run_id),
            details={
                "type": "CRON",
                "schedule": current_time_hhmm,
                "total": total,
                "success": success,
                "errors": errors,
                "duration_seconds": round(duration, 1),
                "log_path": run_logger.get_log_path()
            }
        )
        
        # Notify with disabled devices
        self.notifier.send_summary(total, success, errors, failed_hosts, diff_summary, duration, disabled_devices)
        
        log.info(f"Ejecución programada completada. Éxito: {success}, Errores: {errors}")

