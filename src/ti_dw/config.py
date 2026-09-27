from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv


#carica il file .env se presente
load_dotenv()


@dataclass(frozen=True)
class Settings:
    """Contenitore della configurazione letta da env"""

    database_url: str
    threatfox_auth_key: str | None
    urlhaus_recent_url: str
    threatfox_api_url: str
    http_timeout_seconds: int


def get_settings() -> Settings:
    """Legge la configurazione minima e valida i campi obbligatori"""

    database_url = os.getenv("DATABASE_URL", "").strip()
    if not database_url:
        raise RuntimeError("DATABASE_URL non impostata")

    threatfox_auth_key = os.getenv("THREATFOX_AUTH_KEY")
    if threatfox_auth_key is not None:
        threatfox_auth_key = threatfox_auth_key.strip() or None

    urlhaus_recent_url = os.getenv(
        "URLHAUS_RECENT_URL",
        "https://urlhaus.abuse.ch/downloads/csv_recent/",
    ).strip()

    threatfox_api_url = os.getenv(
        "THREATFOX_API_URL",
        "https://threatfox-api.abuse.ch/api/v1/",
    ).strip()

    http_timeout_seconds = int(os.getenv("HTTP_TIMEOUT_SECONDS", "30"))

    return Settings(
        database_url=database_url,
        threatfox_auth_key=threatfox_auth_key,
        urlhaus_recent_url=urlhaus_recent_url,
        threatfox_api_url=threatfox_api_url,
        http_timeout_seconds=http_timeout_seconds,
    )