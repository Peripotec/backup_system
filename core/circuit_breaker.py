"""
Circuit Breaker pattern for backup groups/vendors.
Pauses a group after consecutive failures to prevent cascading issues.

Usage:
    breaker = CircuitBreaker(failure_threshold=3, reset_seconds=300)
    
    # Before attempting backup:
    if breaker.is_open("HuaweiCore"):
        log.warning("Group HuaweiCore is paused due to failures")
        return  # Skip this device
    
    # After backup:
    if success:
        breaker.record_success("HuaweiCore")
    else:
        breaker.record_failure("HuaweiCore")
"""
import time
from collections import defaultdict
from core.logger import log


class CircuitBreaker:
    """
    Implements the Circuit Breaker pattern for backup groups.
    
    When a group has consecutive failures exceeding the threshold,
    the circuit "opens" and further backups are skipped until reset.
    """
    
    def __init__(self, failure_threshold=3, reset_seconds=300):
        """
        Initialize the circuit breaker.
        
        Args:
            failure_threshold: Number of consecutive failures before opening
            reset_seconds: Seconds to wait before attempting again
        """
        self.failure_threshold = failure_threshold
        self.reset_seconds = reset_seconds
        self.consecutive_failures = defaultdict(int)
        self.open_until = {}
        self.last_failure = {}
    
    def record_success(self, group):
        """
        Record a successful backup. Resets the failure counter.
        
        Args:
            group: The group/vendor identifier
        """
        if group in self.consecutive_failures:
            if self.consecutive_failures[group] > 0:
                log.debug(f"Circuit breaker: {group} success, resetting counter from {self.consecutive_failures[group]}")
            self.consecutive_failures[group] = 0
    
    def record_failure(self, group, error_message=None):
        """
        Record a failed backup. May open the circuit.
        
        Args:
            group: The group/vendor identifier
            error_message: Optional error message for logging
        """
        self.consecutive_failures[group] += 1
        self.last_failure[group] = time.time()
        
        if self.consecutive_failures[group] >= self.failure_threshold:
            self.open_until[group] = time.time() + self.reset_seconds
            log.warning(
                f"Circuit OPEN for '{group}' after {self.consecutive_failures[group]} failures. "
                f"Pausing for {self.reset_seconds}s. Last error: {error_message or 'N/A'}"
            )
        else:
            log.debug(
                f"Circuit breaker: {group} failure #{self.consecutive_failures[group]}, "
                f"threshold is {self.failure_threshold}"
            )
    
    def is_open(self, group):
        """
        Check if the circuit is open (should skip backups).
        
        Args:
            group: The group/vendor identifier
            
        Returns:
            True if backups should be skipped, False otherwise
        """
        if group not in self.open_until:
            return False
        
        if time.time() < self.open_until[group]:
            # Still in cooldown period
            remaining = self.open_until[group] - time.time()
            log.debug(f"Circuit still open for '{group}', {remaining:.0f}s remaining")
            return True
        
        # Reset - cooldown expired
        log.info(f"Circuit CLOSED for '{group}' - cooldown expired, resuming backups")
        del self.open_until[group]
        self.consecutive_failures[group] = 0
        return False
    
    def force_close(self, group):
        """
        Force close a circuit (reset it manually).
        
        Args:
            group: The group/vendor identifier
        """
        if group in self.open_until:
            del self.open_until[group]
        self.consecutive_failures[group] = 0
        log.info(f"Circuit FORCE CLOSED for '{group}'")
    
    def force_open(self, group, duration_seconds=None):
        """
        Force open a circuit (pause backups manually).
        
        Args:
            group: The group/vendor identifier
            duration_seconds: How long to pause (default: reset_seconds)
        """
        duration = duration_seconds or self.reset_seconds
        self.open_until[group] = time.time() + duration
        log.info(f"Circuit FORCE OPEN for '{group}' for {duration}s")
    
    def get_status(self):
        """
        Get the current status of all tracked groups.
        
        Returns:
            Dict with status per group
        """
        status = {}
        now = time.time()
        
        all_groups = set(self.consecutive_failures.keys()) | set(self.open_until.keys())
        for group in all_groups:
            is_open = group in self.open_until and now < self.open_until[group]
            remaining = max(0, self.open_until.get(group, 0) - now) if is_open else 0
            
            status[group] = {
                'consecutive_failures': self.consecutive_failures.get(group, 0),
                'is_open': is_open,
                'remaining_seconds': round(remaining),
                'last_failure': self.last_failure.get(group)
            }
        
        return status
    
    def get_open_circuits(self):
        """
        Get list of currently open circuits.
        
        Returns:
            List of group names with open circuits
        """
        return [group for group in self.open_until if self.is_open(group)]


# Singleton instance for global use
_circuit_breaker = None


def get_circuit_breaker(failure_threshold=3, reset_seconds=300):
    """
    Get the global circuit breaker instance.
    
    Args:
        failure_threshold: Number of consecutive failures before opening
        reset_seconds: Seconds to wait before attempting again
        
    Returns:
        CircuitBreaker instance
    """
    global _circuit_breaker
    if _circuit_breaker is None:
        _circuit_breaker = CircuitBreaker(failure_threshold, reset_seconds)
    return _circuit_breaker
