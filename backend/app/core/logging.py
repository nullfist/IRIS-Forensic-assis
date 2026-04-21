from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

from backend.app.core.config import get_settings


class JsonFormatter(logging.Formatter):
    """Minimal structured JSON formatter suitable for local and container logs."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "extra_data"):
            payload["extra"] = getattr(record, "extra_data")
        return json.dumps(payload, default=str)


def _configure_root_logger() -> None:
    settings = get_settings()
    root_logger = logging.getLogger()
    if root_logger.handlers:
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root_logger.addHandler(handler)
    root_logger.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))


def get_logger(name: str) -> logging.Logger:
    """Return a configured structured logger."""

    _configure_root_logger()
    return logging.getLogger(name)