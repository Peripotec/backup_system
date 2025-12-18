import logging
import os
import sys
from settings import LOG_DIR

def setup_logger(name="backup_system", debug=False):
    """
    Sets up a logger that outputs to console and file.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    # Avoid adding handlers multiple times
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Console Handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File Handler (only if LOG_DIR is writable/exists)
    # in Windows dev environment we might just skip or log to local dir
    try:
        if not os.path.exists(LOG_DIR):
            # Try to create, if fails assume running locally without sudo
            # fallback to local logs dir
            try:
                os.makedirs(LOG_DIR, exist_ok=True)
                log_file = os.path.join(LOG_DIR, "system.log")
            except OSError:
                log_file = "system.log" # Local fallback
        else:
            log_file = os.path.join(LOG_DIR, "system.log")
        
        fh = logging.FileHandler(log_file)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    except Exception as e:
        print(f"Warning: Could not set up file logging: {e}")

    return logger

# Global instance for easy import
log = setup_logger()
