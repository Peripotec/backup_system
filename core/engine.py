import yaml
import time
import os
import shutil
from datetime import datetime
import importlib
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from settings import INVENTORY_FILE, MAX_WORKERS, ARCHIVE_DIR
from core.logger import log
from core.db_manager import DBManager
from core.git_manager import GitManager
from core.notifier import Notifier
from core.vault import get_credentials_for_device
from core.config_manager import get_config_manager

class BackupEngine:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.db = DBManager()
        self.git = GitManager()
        self.notifier = Notifier()
        self.inventory = self._load_inventory()
        self.status_callback = None  # Optional callback for web UI updates

    def _load_inventory(self):
        try:
            with open(INVENTORY_FILE, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            log.error(f"Failed to load inventory: {e}")
            return {}

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
        run_id = self.db.start_run()
        
        # Convert single device to list for backward compatibility
        if target_devices and not isinstance(target_devices, list):
            target_devices = [target_devices]
        
        tasks = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            if 'groups' not in self.inventory:
                log.warning("No groups found in inventory.")
                return

            for group in self.inventory['groups']:
                grp_name = group['name']
                grp_vendor = group['vendor']  # May be empty for mixed groups
                # Get credential_ids for vault lookup (new format)
                grp_credential_ids = group.get('credential_ids', [])

                if target_group and target_group != grp_name:
                    continue

                for device in group['devices']:
                    # Skip disabled devices
                    if device.get('enabled') is False:
                        sysname = device.get('sysname') or device.get('hostname')
                        log.info(f"Skipping disabled device: {sysname} (reason: {device.get('disabled_reason', 'N/A')})")
                        continue
                    
                    # Filter by specific devices list
                    if target_devices:
                        sysname = device.get('sysname')
                        hostname = device.get('hostname')
                        if sysname not in target_devices and hostname not in target_devices:
                            continue
                    
                    # Determine vendor: device-level overrides group-level (for mixed groups)
                    vendor_type = device.get('vendor') or grp_vendor
                    if not vendor_type:
                        log.warning(f"Skipping device {device.get('sysname', device.get('hostname'))}: no vendor defined")
                        continue
                    
                    # Device-specific credential_ids override group, but include group as fallback
                    device_cred_ids = device.get('credential_ids', [])
                    if device_cred_ids:
                        # Device has override - use device creds first, then group creds as fallback
                        all_cred_ids = list(device_cred_ids)
                        for grp_cred in grp_credential_ids:
                            if grp_cred not in all_cred_ids:
                                all_cred_ids.append(grp_cred)
                        device_cred_ids = all_cred_ids
                    else:
                        # No device override - use group credentials
                        device_cred_ids = grp_credential_ids
                    
                    # Submit to pool with credential_ids
                    future = executor.submit(
                        self.process_device, 
                        device, 
                        grp_name, 
                        vendor_type,
                        device_cred_ids
                    )
                    tasks.append(future)

        # Collect Results
        results = []
        for future in concurrent.futures.as_completed(tasks):
            results.append(future.result())

        # Success/Stats
        total = len(results)
        success = sum(1 for r in results if r['status'] == "SUCCESS")
        errors = total - success
        
        failed_hosts = {r['hostname']: r.get('error', 'Unknown') for r in results if r['status'] == "ERROR"}
        diff_summary = {r['hostname']: r['diff'] for r in results if r.get('diff')}

        self.db.end_run(run_id, total, success, errors)
        
        # Notify
        duration = 0 # Not tracking total run duration in var yet, relying on DB
        self.notifier.send_summary(total, success, errors, failed_hosts, diff_summary, duration)
        
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
        run_id = self.db.start_run()
        
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
            self.db.end_run(run_id, 0, 0, 0)
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
        
        # Collect Results
        results = []
        for future in concurrent.futures.as_completed(tasks):
            results.append(future.result())
        
        # Stats
        total = len(results)
        success = sum(1 for r in results if r['status'] == "SUCCESS")
        errors = total - success
        
        failed_hosts = {r['hostname']: r.get('error', 'Unknown') for r in results if r['status'] == "ERROR"}
        diff_summary = {r['hostname']: r['diff'] for r in results if r.get('diff')}
        
        self.db.end_run(run_id, total, success, errors)
        
        # Notify with disabled devices
        duration = 0
        self.notifier.send_summary(total, success, errors, failed_hosts, diff_summary, duration, disabled_devices)
        
        log.info(f"Ejecución programada completada. Éxito: {success}, Errores: {errors}")

