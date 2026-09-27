from __future__ import annotations

import logging
import os


def get_logger(name: str) -> logging.Logger:
    """Restituisce il logger"""

    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=level,
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )

    return logging.getLogger(name)