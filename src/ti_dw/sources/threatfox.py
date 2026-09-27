from __future__ import annotations

from typing import Any

import requests

from ti_dw.config import Settings


def fetch_threatfox_iocs(
    settings: Settings,
    days: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Chiama ThreatFox get_iocs e restituisce gli oggetti IOC grezzi"""

    if not settings.threatfox_auth_key:
        raise RuntimeError("THREATFOX_AUTH_KEY non impostata")

    if days < 1 or days > 7:
        raise ValueError("days deve essere compreso tra 1 e 7")

    headers = {
        "Auth-Key": settings.threatfox_auth_key,
    }

    payload = {
        "query": "get_iocs",
        "days": days,
    }

    response = requests.post(
        settings.threatfox_api_url,
        headers=headers,
        json=payload,
        timeout=settings.http_timeout_seconds,
    )
    response.raise_for_status()

    body = response.json()
    query_status = body.get("query_status")

    if query_status != "ok":
        raise RuntimeError(f"ThreatFox ha risposto con query_status={query_status}")

    data = body.get("data") or []

    trace_meta = {
        "source": "threatfox",
        "request_url": settings.threatfox_api_url,
        "http_status": response.status_code,
        "query_status": query_status,
        "days": days,
    }

    return data, trace_meta