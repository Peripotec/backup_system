import yaml
import time
import importlib
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from settings import INVENTORY_FILE, MAX_WORKERS
from core.logger import log
from core.db_manager import DBManager
from core.git_manager import GitManager
from core.notifier import Notifier

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

    def process_device(self, device, group_name="Default", vendor_type="generic"):
        """
        Worker function to process a single device.
        """
        hostname = device['hostname']
        start_time = time.time()
        
        log.info(f"Starting backup for {hostname} ({vendor_type})")
        
        # Notify UI that we're starting this device
        if self.status_callback:
            self.status_callback(hostname, "start")
        
        if self.dry_run:
            time.sleep(0.5) # Simulate work
            log.info(f"[DRY-RUN] Backup simulated for {hostname}")
            self.db.record_job(hostname, vendor_type, group_name, "SUCCESS", "Dry Run", duration=0.5)
            if self.status_callback:
                self.status_callback(hostname, "success", "Dry Run")
            return {"status": "SUCCESS", "hostname": hostname, "diff": None}

        # Real Execution
        try:
            VendorClass = self._get_vendor_plugin(vendor_type)
            if not VendorClass:
                raise ValueError(f"Unknown vendor: {vendor_type}")
            
            plugin = VendorClass(device, self.db, self.git)
            archive_path, size, changed = plugin.backup()
            
            duration = time.time() - start_time
            msg = f"{size} bytes"
            if changed:
                msg += " (cambios)"
                diff = self.git.get_diff(plugin.hostname + ".cfg")
            else:
                diff = None

            self.db.record_job(
                hostname, vendor_type, group_name, "SUCCESS", msg, 
                file_path=archive_path, file_size=size, duration=duration, changed=changed
            )
            
            log.info(f"Success: {hostname} ({size} bytes)")
            
            # Notify UI of success
            if self.status_callback:
                self.status_callback(hostname, "success", msg)
            
            return {"status": "SUCCESS", "hostname": hostname, "diff": diff}

        except Exception as e:
            duration = time.time() - start_time
            log.error(f"Error backup {hostname}: {e}")
            self.db.record_job(
                hostname, vendor_type, group_name, "ERROR", str(e), 
                duration=duration
            )
            
            # Notify UI of error
            if self.status_callback:
                self.status_callback(hostname, "error", str(e))
            
            return {"status": "ERROR", "hostname": hostname, "error": str(e)}


    def run(self, target_group=None, target_device=None):
        """
        Main runner. Spawns threads.
        target_group: filter by group name
        target_device: filter by device hostname
        """
        log.info(f"Starting Backup Run (Dry Run={self.dry_run})")
        run_id = self.db.start_run()
        
        tasks = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            if 'groups' not in self.inventory:
                log.warning("No groups found in inventory.")
                return

            for group in self.inventory['groups']:
                grp_name = group['name']
                vendor_type = group['vendor']
                grp_creds = group.get('credentials', {})

                if target_group and target_group != grp_name:
                    continue

                for device in group['devices']:
                    # Filter by specific device if requested
                    if target_device and device['hostname'] != target_device:
                        continue
                    
                    # Merge credentials
                    # Device specific creds override group creds
                    full_device_info = device.copy()
                    if 'credentials' not in full_device_info:
                        full_device_info['credentials'] = grp_creds
                    
                    # Submit to pool
                    future = executor.submit(self.process_device, full_device_info, grp_name, vendor_type)
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
