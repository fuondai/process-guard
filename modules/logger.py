#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Logger module for Process Doppelgänging Detector
------------------------------------------------
Handles logging for the detector.
"""
import os
import logging
from datetime import datetime

# ANSI Color codes for terminal output - Windows compatible version
class Colors:
    # Enable Windows ANSI color support
    import os
    os.system('')  # This is required to enable ANSI color codes in Windows terminal
    
    RESET = '\033[0m'
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'

# Custom formatter for colored console output
class ColoredFormatter(logging.Formatter):
    # Check if we're running in a Windows environment
    import platform
    is_windows = platform.system() == 'Windows'
    
    LEVEL_COLORS = {
        'DEBUG': Colors.BLUE,
        'INFO': Colors.GREEN,
        'WARNING': Colors.YELLOW,
        'ERROR': Colors.RED,
        'CRITICAL': Colors.BG_RED + Colors.WHITE + Colors.BOLD
    }
    
    THREAT_LEVELS = {
        'LOW': Colors.GREEN,
        'MEDIUM': Colors.YELLOW,
        'HIGH': Colors.RED + Colors.BOLD,
    }
    
    def __init__(self, fmt=None, datefmt=None, style='%', use_colors=True):
        # Enable ANSI colors on Windows
        if self.is_windows and use_colors:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # Enable ANSI processing on Windows
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        self.use_colors = use_colors
        super().__init__(fmt, datefmt, style)
    
    def format(self, record):
        # Create a copy of the record to not modify the original
        original_levelname = record.levelname
        original_message = record.getMessage()
        
        # Only add colors if enabled (for console, not for file)
        if self.use_colors:
            # Check if this is a threat level message
            if hasattr(record, 'threat_level'):
                level_color = self.THREAT_LEVELS.get(record.threat_level, Colors.RESET)
                record.levelname = f"{level_color}[{record.threat_level}]{Colors.RESET}"
            else:
                # Regular message formatting
                level_color = self.LEVEL_COLORS.get(record.levelname, Colors.RESET)
                record.levelname = f"{level_color}{record.levelname}{Colors.RESET}"
        elif hasattr(record, 'threat_level'):
            # No colors, but still format threat level
            record.levelname = f"[{record.threat_level}]"
            
        result = super().format(record)
        
        # Restore original record attributes
        record.levelname = original_levelname
        
        return result

# Custom logger with threat levels
class DoppelgangerLogger(logging.Logger):
    def threat(self, threat_level, msg, *args, **kwargs):
        """Log a message with threat level (LOW, MEDIUM, HIGH)"""
        if self.isEnabledFor(logging.WARNING):
            record = self.makeRecord(
                self.name, logging.WARNING, 
                kwargs.get('filename', ''), kwargs.get('lineno', 0), 
                msg, args, None, func=kwargs.get('func', None),
                extra={'threat_level': threat_level}
            )
            self.handle(record)

# Register our custom logger class
logging.setLoggerClass(DoppelgangerLogger)

# Global logger instance
_logger = None

def setup_logger(log_file=None, log_level=logging.INFO):
    """Setup and return a logger instance with colored output"""
    global _logger
    
    if _logger is not None:
        return _logger
        
    # Create logger
    logger = logging.getLogger('doppelganger_detector')
    logger.setLevel(log_level)
    
    # Create a formatter for console output with colors
    colored_formatter = ColoredFormatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        '%Y-%m-%d %H:%M:%S',
        use_colors=True
    )
    
    # Create a formatter for file output without colors
    file_formatter = ColoredFormatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        '%Y-%m-%d %H:%M:%S',
        use_colors=False
    )
    
    # Create console handler with color formatter
    console = logging.StreamHandler()
    console.setLevel(log_level)
    console.setFormatter(colored_formatter)
    logger.addHandler(console)
    
    # Create file handler with standard formatter if log_file is specified
    if log_file:
        # Use the specified log file
        file_path = log_file
    else:
        # Create default log file in logs directory
        log_dir = "logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        file_path = os.path.join(log_dir, f"detector_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    file_handler = logging.FileHandler(file_path)
    file_handler.setLevel(log_level)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    _logger = logger
    return logger

def get_logger():
    """Get the logger instance."""
    global _logger
    
    # Create a default logger if none exists
    if _logger is None:
        _logger = setup_logger()
    
    return _logger
