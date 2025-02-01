import logging

logger = logging.getLogger("fastapi_nextauth_jwt")

def get_logger() -> logging.Logger:
    """
    Get the library's logger instance.
    The logger can be configured using standard Python logging configuration.

    Returns:
        logging.Logger: The library's logger instance

    Example:
        >>> import logging
        >>> logging.basicConfig(level=logging.DEBUG)  # Configure root logger
        >>>
        >>> # Or configure only this library's logger
        >>> logging.getLogger("fastapi_nextauth_jwt").setLevel(logging.DEBUG)
    """
    return logger