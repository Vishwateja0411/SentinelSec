import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict


class JSONFormatter(logging.Formatter):
    """
    Format log records as structured JSON entries.
    Ensures safe formatting without sensitive leakage.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include structured extra fields if present
        if hasattr(record, "structured_data") and isinstance(record.structured_data, dict):
            log_entry["data"] = record.structured_data

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


def setup_logging(level: str = "INFO") -> None:
    """Configure root logger with structured JSON formatting."""
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Avoid duplicate handlers on re-init
    if root_logger.handlers:
        for handler in root_logger.handlers:
            root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    root_logger.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Return a logger instance for the given module name."""
    return logging.getLogger(name)


def log_structured(logger: logging.Logger, level: int, msg: str, **kwargs: Any) -> None:
    """Helper to emit structured log records with arbitrary extra key-value pairs."""
    extra = {"structured_data": kwargs}
    logger.log(level, msg, extra=extra)
