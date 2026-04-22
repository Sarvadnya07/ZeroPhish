import os
import sys
from loguru import logger

def setup_logger():
    # Remove default logger
    logger.remove()

    # Add stdout logger with JSON formatting for production observability
    log_format = "{time:YYYY-MM-DDTHH:mm:ss.SSSZ} | {level} | {name}:{function}:{line} | {message}"
    
    use_json = os.getenv("LOG_JSON", "true").lower() == "true"
    
    if use_json:
        logger.add(
            sys.stdout, 
            format="{message}",
            level=os.getenv("LOG_LEVEL", "INFO"),
            serialize=True
        )
    else:
        logger.add(
            sys.stdout,
            format=log_format,
            level=os.getenv("LOG_LEVEL", "INFO"),
            colorize=True
        )

    return logger

setup_logger()
