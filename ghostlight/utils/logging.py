import logging
import sys
from pathlib import Path


def setup_logger(name: str = "ghostlight", level: int = logging.INFO, log_file: str | None = None):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str = "ghostlight"):
    """Get or create a logger with console output"""
    logger = logging.getLogger(name)
    
    # Initialize logger if not already done
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        
        # Simple console handler without timestamp for cleaner output
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(console_handler)
        
        # Ensure output is flushed immediately
        sys.stdout.flush()
    
    return logger

