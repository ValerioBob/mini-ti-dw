from __future__ import annotations

from datetime import date, datetime, timezone
from uuid import uuid4

from ti_dw.config import get_settings
from ti_dw.db import get_connection, insert_raw_records
from ti_dw.logging import get_logger
from ti_dw.sources.threatfox import fetch_threatfox_iocs
from ti_dw.sources.urlhaus import fetch_urlhaus_recent


logger = get_logger(__name__)


def ingest_urlhaus(snapshot_date: date | None = None) -> int:
    """Scarica URLhaus e salva i payload grezzi nello staging raw"""

    settings = get_settings()
    batch_id = uuid4()
    logical_snapshot_date = snapshot_date or date.today()

    logger.info("inizio ingest urlhaus batch_id=%s", batch_id)

    records, base_trace = fetch_urlhaus_recent(settings)

    fetched_at = datetime.now(timezone.utc).isoformat()
    rows = []

    #trasformazione tecnica minima per l insert raw
    for record in records:
        trace_meta = {
            **base_trace,
            "fetched_at": fetched_at,
        }

        rows.append(
            {
                "ingest_batch_id": batch_id,
                "snapshot_date": logical_snapshot_date,
                "source_record_id": record.get("id"),
                "payload_json": record,
                "trace_meta": trace_meta,
            }
        )

    with get_connection(settings) as conn:
        inserted = insert_raw_records(conn, "raw_urlhaus", rows)

    logger.info("fine ingest urlhaus batch_id=%s inserted=%s", batch_id, inserted)
    return inserted


def ingest_threatfox(days: int = 1, snapshot_date: date | None = None) -> int:
    """Scarica i recent IOCs ThreatFox e salva i payload grezzi nello staging raw"""

    settings = get_settings()
    batch_id = uuid4()
    logical_snapshot_date = snapshot_date or date.today()

    logger.info("inizio ingest threatfox batch_id=%s days=%s", batch_id, days)

    records, base_trace = fetch_threatfox_iocs(settings, days=days)

    fetched_at = datetime.now(timezone.utc).isoformat()
    rows = []

    #trasformazione tecnica minima per l insert raw
    for record in records:
        trace_meta = {
            **base_trace,
            "fetched_at": fetched_at,
        }

        rows.append(
            {
                "ingest_batch_id": batch_id,
                "snapshot_date": logical_snapshot_date,
                "source_record_id": record.get("id"),
                "payload_json": record,
                "trace_meta": trace_meta,
            }
        )

    with get_connection(settings) as conn:
        inserted = insert_raw_records(conn, "raw_threatfox", rows)

    logger.info(
        "fine ingest threatfox batch_id=%s days=%s inserted=%s",
        batch_id,
        days,
        inserted,
    )
    return inserted