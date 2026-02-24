import logging
import os
from datetime import datetime
import yaml

def setup_logger(module_name: str) -> logging.Logger:
    """
    Sets up a logger for a specific module, logging to both file and console.
    Ensures logs are stored in the /Nox/logs directory.
    """
    # Load config to get log directory and level
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.yaml')
    log_dir = './logs'
    log_level = logging.INFO
    
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            log_dir = config.get('global', {}).get('log_dir', './logs')
            level_str = config.get('logging', {}).get('level', 'INFO')
            log_level = getattr(logging, level_str.upper(), logging.INFO)
    except Exception:
        pass

    # Ensure log directory exists
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Log filename: <module>_<timestamp>.log
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"{module_name}_{timestamp}.log")

    logger = logging.getLogger(module_name)
    logger.setLevel(log_level)

    # Avoid adding duplicate handlers if the logger was already configured
    if not logger.handlers:
        # Format: [TIMESTAMP] [LEVEL] [MODULE] Message
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s', 
                                      datefmt='%Y-%m-%dT%H:%M:%S%z')

        # File handler
        fh = logging.FileHandler(log_file)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

        # Console handler (standard logging doesn't use rich by default here, 
        # but tools will use rich for their output. This is for the backend log stream.)
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        # logger.addHandler(ch) # We might not want duplicate logs on console if rich is used.

    # Prevent log messages from being propagated to the root logger twice
    logger.propagate = False

    return logger

def audit_log(logger: logging.Logger, operator: str, target: str, module: str, arguments: str, result: str):
    """
    Action audit trail required by Raven-Security standards.
    """
    msg = f"AUDIT: Op={operator} Target={target} Module={module} Args={arguments} Result={result}"
    logger.info(msg)
