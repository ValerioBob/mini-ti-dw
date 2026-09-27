from __future__ import annotations

import ipaddress
import re
from datetime import date, datetime
from typing import Any


def normalize_urlhaus_rows(raw_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalizza le righe raw URLhaus e restituisce solo i record validi"""

    normalized_rows: list[dict[str, Any]] = []

    #normalizzazione riga per riga
    for raw_row in raw_rows:
        canonical_row = _normalize_urlhaus_row(raw_row)
        if canonical_row is not None:
            normalized_rows.append(canonical_row)

    return normalized_rows


def normalize_threatfox_rows(raw_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalizza le righe raw ThreatFox e restituisce solo i record validi"""

    normalized_rows: list[dict[str, Any]] = []

    #normalizzazione riga per riga
    for raw_row in raw_rows:
        canonical_row = _normalize_threatfox_row(raw_row)
        if canonical_row is not None:
            normalized_rows.append(canonical_row)

    return normalized_rows


def _normalize_urlhaus_row(raw_row: dict[str, Any]) -> dict[str, Any] | None:
    """Converte una riga raw URLhaus nel formato canonico"""

    payload = raw_row.get("payload_json") or {}
    indicator_value = _normalize_url_value(payload.get("url"))
    event_time = _parse_urlhaus_event_time(payload.get("dateadded"))

    if indicator_value is None or event_time is None:
        return None

    return {
        "source_name": "urlhaus",
        "raw_table_name": "raw_urlhaus",
        "raw_id": raw_row["raw_id"],
        "source_record_id": raw_row.get("source_record_id"),
        "indicator_type": "url",
        "indicator_value": indicator_value,
        "event_time": event_time,
        "day_bucket": _build_day_bucket(event_time),
        "status": _map_urlhaus_status(payload),
        "tags": _parse_urlhaus_tags(payload),
        "context_json": _build_urlhaus_context(payload),
    }


def _normalize_threatfox_row(raw_row: dict[str, Any]) -> dict[str, Any] | None:
    """Converte una riga raw ThreatFox nel formato canonico"""

    payload = raw_row.get("payload_json") or {}
    ioc_type = _clean_text(payload.get("ioc_type"))
    indicator_type = _map_threatfox_indicator_type(ioc_type)
    event_time = _parse_threatfox_event_time(payload.get("first_seen"))

    if indicator_type is None or event_time is None:
        return None

    indicator_value, extracted_port = _normalize_threatfox_indicator_value(
        ioc_type=ioc_type,
        ioc_value=payload.get("ioc"),
    )

    if indicator_value is None:
        return None

    return {
        "source_name": "threatfox",
        "raw_table_name": "raw_threatfox",
        "raw_id": raw_row["raw_id"],
        "source_record_id": raw_row.get("source_record_id"),
        "indicator_type": indicator_type,
        "indicator_value": indicator_value,
        "event_time": event_time,
        "day_bucket": _build_day_bucket(event_time),
        "status": "unknown",
        "tags": _parse_threatfox_tags(payload),
        "context_json": _build_threatfox_context(payload, extracted_port),
    }


def _parse_urlhaus_event_time(value: Any) -> datetime | None:
    """Parsa la data URLhaus nel formato osservato senza timezone"""

    clean_value = _clean_text(value)
    if clean_value is None:
        return None

    try:
        return datetime.strptime(clean_value, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _parse_threatfox_event_time(value: Any) -> datetime | None:
    """Parsa la data ThreatFox nel formato osservato con suffisso UTC"""

    clean_value = _clean_text(value)
    if clean_value is None:
        return None

    try:
        return datetime.strptime(clean_value, "%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return None


def _build_day_bucket(event_time: datetime) -> date:
    """Deriva il bucket giornaliero dal timestamp evento"""

    return event_time.date()


def _map_urlhaus_status(payload: dict[str, Any]) -> str:
    """Mappa lo stato URLhaus nel dominio canonico"""

    status_value = (_clean_text(payload.get("url_status")) or "").lower()

    if status_value == "online":
        return "online"

    if status_value == "offline":
        return "offline"

    return "unknown"


def _parse_urlhaus_tags(payload: dict[str, Any]) -> list[str]:
    """Legge e pulisce i tag URLhaus separati da virgola"""

    raw_tags = _clean_text(payload.get("tags"))
    if raw_tags is None:
        return []

    return _deduplicate_tags(re.split(r"\s*,\s*", raw_tags))


def _parse_threatfox_tags(payload: dict[str, Any]) -> list[str]:
    """Legge e pulisce i tag ThreatFox espressi come array json"""

    raw_tags = payload.get("tags")
    if not isinstance(raw_tags, list):
        return []

    return _deduplicate_tags(raw_tags)


def _map_threatfox_indicator_type(ioc_type: str | None) -> str | None:
    """Mappa il tipo ThreatFox nel dominio canonico ammesso"""

    if ioc_type == "url":
        return "url"

    if ioc_type == "domain":
        return "domain"

    if ioc_type == "ip":
        return "ip"

    if ioc_type == "ip:port":
        return "ip"

    return None


def _normalize_threatfox_indicator_value(
    ioc_type: str | None,
    ioc_value: Any,
) -> tuple[str | None, str | None]:
    """Normalizza il valore ThreatFox e restituisce anche la porta se presente"""

    clean_value = _clean_text(ioc_value)
    if clean_value is None:
        return None, None

    if ioc_type == "domain":
        return _normalize_domain(clean_value), None

    if ioc_type == "url":
        return _normalize_url_value(clean_value), None

    if ioc_type == "ip":
        return _normalize_ip_value(clean_value), None

    if ioc_type == "ip:port":
        return _extract_ip_port(clean_value)

    return None, None


def _normalize_domain(value: str | None) -> str | None:
    """Normalizza un dominio con regole leggere"""

    clean_value = _clean_text(value)
    if clean_value is None:
        return None

    normalized_value = clean_value.lower().rstrip(".")
    return normalized_value or None


def _normalize_url_value(value: str | None) -> str | None:
    """Normalizza una url senza riscritture aggressive"""

    return _clean_text(value)


def _normalize_ip_value(value: str | None) -> str | None:
    """Normalizza un indirizzo ip nel formato canonico"""

    clean_value = _clean_text(value)
    if clean_value is None:
        return None

    try:
        return str(ipaddress.ip_address(clean_value))
    except ValueError:
        return None


def _extract_ip_port(value: str) -> tuple[str | None, str | None]:
    """Estrae ip e porta dai formati ipv4 porta e ipv6 tra parentesi"""

    ipv6_match = re.fullmatch(r"\[([0-9A-Fa-f:]+)\]:(\d+)", value)
    if ipv6_match is not None:
        ip_value = _normalize_ip_value(ipv6_match.group(1))
        port_value = ipv6_match.group(2)
        return ip_value, port_value

    ipv4_match = re.fullmatch(r"([0-9.]+):(\d+)", value)
    if ipv4_match is not None:
        ip_value = _normalize_ip_value(ipv4_match.group(1))
        port_value = ipv4_match.group(2)
        return ip_value, port_value

    return None, None


def _build_urlhaus_context(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Costruisce il contesto leggero per URLhaus"""

    context = {
        "threat": _clean_text(payload.get("threat")),
        "reporter": _clean_text(payload.get("reporter")),
        "last_online": _clean_text(payload.get("last_online")),
        "urlhaus_link": _clean_text(payload.get("urlhaus_link")),
    }

    return _strip_none_values(context)


def _build_threatfox_context(
    payload: dict[str, Any],
    extracted_port: str | None,
) -> dict[str, Any] | None:
    """Costruisce il contesto leggero per ThreatFox"""

    context = {
        "ioc_original": _clean_text(payload.get("ioc")),
        "ioc_type_original": _clean_text(payload.get("ioc_type")),
        "reporter": _clean_text(payload.get("reporter")),
        "last_seen": _clean_text(payload.get("last_seen")),
        "reference": _clean_text(payload.get("reference")),
        "threat_type": _clean_text(payload.get("threat_type")),
        "ioc_type_desc": _clean_text(payload.get("ioc_type_desc")),
        "malware": _clean_text(payload.get("malware")),
        "malware_alias": _clean_text(payload.get("malware_alias")),
        "malware_printable": _clean_text(payload.get("malware_printable")),
        "malware_malpedia": _clean_text(payload.get("malware_malpedia")),
        "threat_type_desc": _clean_text(payload.get("threat_type_desc")),
        "is_compromised": payload.get("is_compromised"),
        "confidence_level": payload.get("confidence_level"),
        "port": extracted_port,
    }

    return _strip_none_values(context)


def _strip_none_values(data: dict[str, Any]) -> dict[str, Any] | None:
    """Rimuove i campi nulli dal contesto"""

    clean_data = {key: value for key, value in data.items() if value is not None}
    return clean_data or None


def _deduplicate_tags(values: list[Any]) -> list[str]:
    """Pulisce i tag e rimuove i duplicati mantenendo l ordine"""

    clean_tags: list[str] = []
    seen_tags: set[str] = set()

    #pulizia e deduplica stabile
    for value in values:
        clean_value = _clean_text(value)
        if clean_value is None:
            continue

        if clean_value in seen_tags:
            continue

        seen_tags.add(clean_value)
        clean_tags.append(clean_value)

    return clean_tags


def _clean_text(value: Any) -> str | None:
    """Converte in stringa pulita e restituisce None per valori vuoti"""

    if value is None:
        return None

    clean_value = str(value).strip()
    return clean_value or None