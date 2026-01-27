"""
Run-specific logging for backup executions.
Creates individual log files per run for traceability.

Usage:
    run_logger = RunLogger(run_id, run_type="CRON", username=None)
    run_logger.start(total_devices=45)
    run_logger.log("Connected to device", device="Router-A")
    run_logger.log_success("Router-A", size=245, changed=True)
    run_logger.log_error("Switch-B", "Connection refused")
    run_logger.end(success=43, errors=2, duration_seconds=300)
"""
import os
import logging
from datetime import datetime
from settings import LOG_DIR


class RunLogger:
    """
    Creates an individual log file for each backup run execution.
    Provides structured logging with device-specific prefixes.
    """
    
    def __init__(self, run_id, run_type="MANUAL", username=None):
        """
        Initialize a run logger.
        
        Args:
            run_id: Database ID of the run
            run_type: "CRON" or "MANUAL"
            username: Optional username for manual runs
        """
        self.run_id = run_id
        self.run_type = run_type
        self.username = username
        self.start_time = datetime.now()
        self.log_path = self._create_log_file()
        self._setup_logger()
        self.device_results = {}  # Track per-device outcomes
    
    def _create_log_file(self):
        """Create the log file path and ensure directory exists."""
        runs_dir = os.path.join(LOG_DIR, "runs")
        os.makedirs(runs_dir, exist_ok=True)
        
        timestamp = self.start_time.strftime("%Y-%m-%d_%H-%M")
        if self.username:
            filename = f"run_{self.run_id}_{timestamp}_{self.run_type}_{self.username}.log"
        else:
            filename = f"run_{self.run_id}_{timestamp}_{self.run_type}.log"
        
        return os.path.join(runs_dir, filename)
    
    def _setup_logger(self):
        """Configure the file logger."""
        self.logger = logging.getLogger(f"run_{self.run_id}")
        self.logger.setLevel(logging.DEBUG)
        # Prevent propagation to root logger
        self.logger.propagate = False
        
        handler = logging.FileHandler(self.log_path, encoding='utf-8')
        handler.setFormatter(logging.Formatter(
            '[%(asctime)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        self.logger.addHandler(handler)
    
    def log(self, message, device=None):
        """
        Log a message, optionally prefixed with device name.
        
        Args:
            message: The message to log
            device: Optional device name for prefix
        """
        if device:
            self.logger.info(f"[{device}] {message}")
        else:
            self.logger.info(message)
    
    def log_debug(self, message, device=None):
        """Log a debug-level message."""
        if device:
            self.logger.debug(f"[{device}] {message}")
        else:
            self.logger.debug(message)
    
    def log_success(self, device, size=0, changed=False, duration=0):
        """Log a successful backup."""
        change_indicator = " (CHANGED)" if changed else ""
        msg = f"✓ SUCCESS - {size} bytes{change_indicator} in {duration:.1f}s"
        self.logger.info(f"[{device}] {msg}")
        self.device_results[device] = {'status': 'SUCCESS', 'size': size, 'changed': changed}
    
    def log_error(self, device, error_message, duration=0):
        """Log a failed backup."""
        msg = f"✗ ERROR - {error_message} in {duration:.1f}s"
        self.logger.error(f"[{device}] {msg}")
        self.device_results[device] = {'status': 'ERROR', 'error': error_message}
    
    def log_skip(self, device, reason):
        """Log a skipped device."""
        self.logger.info(f"[{device}] ⊘ SKIPPED - {reason}")
        self.device_results[device] = {'status': 'SKIPPED', 'reason': reason}
    
    def start(self, total_devices):
        """Log the start of a run."""
        self.log(f"{'='*60}")
        self.log(f"RUN {self.run_id} STARTED ({self.run_type})")
        self.log(f"{'='*60}")
        self.log(f"Start Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        if self.username:
            self.log(f"Triggered by: {self.username}")
        self.log(f"Devices to process: {total_devices}")
        self.log(f"-" * 60)
    
    def end(self, success, errors, duration_seconds):
        """Log the end of a run with summary."""
        self.log(f"-" * 60)
        self.log(f"{'='*60}")
        self.log(f"RUN {self.run_id} COMPLETED")
        self.log(f"{'='*60}")
        self.log(f"End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log(f"Duration: {duration_seconds:.0f}s ({duration_seconds/60:.1f} min)")
        self.log(f"Results: {success} SUCCESS, {errors} ERRORS")
        
        # List failed devices if any
        failed = [d for d, r in self.device_results.items() if r['status'] == 'ERROR']
        if failed:
            self.log(f"\nFailed devices:")
            for device in failed:
                error = self.device_results[device].get('error', 'Unknown')
                self.log(f"  - {device}: {error}")
        
        # List changed devices
        changed = [d for d, r in self.device_results.items() 
                   if r['status'] == 'SUCCESS' and r.get('changed')]
        if changed:
            self.log(f"\nDevices with config changes: {len(changed)}")
            for device in changed:
                self.log(f"  - {device}")
        
        self.log(f"\nLog file: {self.log_path}")
    
    def get_log_path(self):
        """Return the path to the log file."""
        return self.log_path
    
    def close(self):
        """Close the logger and release handlers."""
        for handler in self.logger.handlers[:]:
            handler.close()
            self.logger.removeHandler(handler)
