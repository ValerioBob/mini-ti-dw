from __future__ import annotations

import csv
from typing import Any

import requests

from ti_dw.config import Settings


def fetch_urlhaus_recent(settings: Settings) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Scarica il feed recente URLhaus e restituisce le righe come dizionari"""

    response = requests.get(
        settings.urlhaus_recent_url,
        timeout=settings.http_timeout_seconds,
    )
    response.raise_for_status()

    lines = response.text.splitlines()

    header_line: str | None = None
    data_lines: list[str] = []

    #ricostruzione corretta di header e righe dati
    for line in lines:
        stripped = line.strip()

        if not stripped:
            continue

        if stripped.startswith("#"):
            candidate = stripped.lstrip("#").strip()

            #la riga header del feed inizia con # id,...
            if candidate.lower().startswith("id,"):
                header_line = candidate

            continue

        data_lines.append(line)

    if header_line is None:
        raise RuntimeError("header CSV URLhaus non trovato")

    reader = csv.DictReader([header_line, *data_lines])

    records: list[dict[str, Any]] = []
    for row in reader:
        records.append(dict(row))

    trace_meta = {
        "source": "urlhaus",
        "request_url": settings.urlhaus_recent_url,
        "http_status": response.status_code,
    }

    return records, trace_meta