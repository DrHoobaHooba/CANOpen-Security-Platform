"""Logging utilities for consistent application logging.

Provides centralized logging configuration with support for multiple
output levels, formatting, and structured logging hooks.
"""

import logging
import sys
from typing import Optional, Dict, Any


# Global logging configuration
_configured = False
_root_logger: Optional[logging.Logger] = None


def configure_logging(
    level: int = logging.INFO,
    format_string: Optional[str] = None,
    log_file: Optional[str] = None,
    use_colored_output: bool = True,
) -> None:
    """Configure application-wide logging.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_string: Log format string; uses default if None
        log_file: Optional file path to log to
        use_colored_output: Use colors in console output if available

    Raises:
        ValueError: If level is invalid
    """
    global _configured, _root_logger

    if not isinstance(level, int) or level not in (
        logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL
    ):
        raise ValueError(f"Invalid logging level: {level}")

    # Use default format if not provided
    if format_string is None:
        format_string = (
            "%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s"
        )

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # Capture all levels, filter in handlers

    # Remove any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create formatter
    formatter = logging.Formatter(format_string)

    # Console handler (with level)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Optional file handler
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
            root_logger.info("Logging to file: %s", log_file)
        except IOError as e:
            root_logger.warning("Failed to open log file '%s': %s", log_file, e)

    _configured = True
    _root_logger = root_logger

    root_logger.debug(
        "Logging configured (level=%s, format=%s)",
        logging.getLevelName(level), format_string
    )


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for a module.

    Args:
        name: Module name (typically __name__)

    Returns:
        Configured logger instance
    """
    # Ensure logging is configured
    if not _configured:
        configure_logging()

    return logging.getLogger(name)


def set_module_level(name: str, level: int) -> None:
    """Set logging level for a specific module.

    Useful for reducing noise from verbose modules.

    Args:
        name: Module name
        level: Logging level

    Raises:
        ValueError: If level is invalid
    """
    if level not in (logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL):
        raise ValueError(f"Invalid logging level: {level}")

    logger = logging.getLogger(name)
    logger.setLevel(level)


def enable_debug(modules: Optional[list] = None) -> None:
    """Enable debug logging for specific modules.

    Args:
        modules: List of module names to debug; if None, enables all
    """
    if modules is None:
        # Enable debug for all
        logging.getLogger().setLevel(logging.DEBUG)
        for handler in logging.getLogger().handlers:
            handler.setLevel(logging.DEBUG)
    else:
        # Enable debug for specific modules
        for module_name in modules:
            set_module_level(module_name, logging.DEBUG)


def disable_debug(modules: Optional[list] = None) -> None:
    """Disable debug logging.

    Args:
        modules: List of modules to quiet; if None, resets to INFO
    """
    if modules is None:
        logging.getLogger().setLevel(logging.INFO)
    else:
        for module_name in modules:
            set_module_level(module_name, logging.INFO)


# Pre-configure on import
if not _configured:
    configure_logging(level=logging.INFO)
