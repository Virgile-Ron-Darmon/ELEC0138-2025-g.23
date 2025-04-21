"""
A custom logging module that provides colored console output and file logging capabilities.
This module includes a ColorFormatter for console output and a main logger class that
handles both console and file logging with appropriate formatting.
"""

import logging
import inspect
import os


class ColorFormatter(logging.Formatter):
    """
    A custom formatter that adds color to log messages based on their level.
    """
    
    COLORS = {
        logging.DEBUG: "\033[94m",    # Blue
        logging.INFO: "\033[92m",     # Green
        logging.WARNING: "\033[93m",  # Yellow
        logging.ERROR: "\033[91m",    # Red
        logging.CRITICAL: "\033[95m", # Magenta
    }
    RESET = "\033[0m"  # Reset color

    def format(self, record):
        """Format the log record with appropriate coloring."""
        log_color = self.COLORS.get(record.levelno, self.RESET)
        message = super().format(record)
        return f"{log_color}{message}{self.RESET}"


class Logger:
    """
    A custom logger class that provides both console and file logging capabilities.
    Includes file path, class name, and method name in log messages.
    """
    
    def __init__(self, log_file='app.log', log_level=logging.INFO):
        """Initialize the logger with specified file and level settings."""
        self.logger = logging.getLogger('BasicLogger')
        self.logger.setLevel(log_level)

        if not self.logger.hasHandlers():
            # Format: timestamp [path/to/file.py:Class.method] [LEVEL] message
            log_format = '%(asctime)s [%(context)s] [%(levelname)s] %(message)s'
            
            file_formatter = logging.Formatter(log_format)
            console_formatter = ColorFormatter(log_format)

            console_handler = logging.StreamHandler()
            console_handler.setFormatter(console_formatter)

            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(file_formatter)

            self.logger.addHandler(console_handler)
            self.logger.addHandler(file_handler)

    def _get_context(self):
        """
        Get the context of where the log was called from.
        Returns formatted string: path/to/file.py:Class.method or path/to/file.py:method
        """
        # Get the caller's frame (2 frames up to skip the logging function)
        frame = inspect.currentframe().f_back.f_back
        
        # Get file path and convert to relative path
        file_path = inspect.getframeinfo(frame).filename
        rel_path = os.path.relpath(file_path)
        
        # Get function name
        func_name = frame.f_code.co_name
        
        # Try to get class name if method is part of a class
        try:
            class_name = frame.f_locals['self'].__class__.__name__
            return f"{rel_path}:{class_name}.{func_name}"
        except (KeyError, AttributeError):
            # If not in a class method, just return the function name
            return f"{rel_path}:{func_name}"

    def log(self, message, level=logging.INFO):
        """
        Log a message with the specified level.
        
        Args:
            message (str): The message to log
            level: The logging level to use (default: logging.INFO)
        """
        extra = {'context': self._get_context()}
        
        if level == logging.DEBUG:
            self.logger.debug(message, extra=extra)
        elif level == logging.INFO:
            self.logger.info(message, extra=extra)
        elif level == logging.WARNING:
            self.logger.warning(message, extra=extra)
        elif level == logging.ERROR:
            self.logger.error(message, extra=extra)
        elif level == logging.CRITICAL:
            self.logger.critical(message, extra=extra)
        else:
            self.logger.info(message, extra=extra)