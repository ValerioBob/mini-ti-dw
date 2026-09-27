from __future__ import annotations

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from ti_dw.canonical.dedup import deduplicate_canonical_rows
from ti_dw.canonical.normalize import normalize_threatfox_rows, normalize_urlhaus_rows
from ti_dw.config import get_settings
from ti_dw.db import get_connection
from ti_dw.logging import get_logger


logger = get_logger(__name__)


def main() -> None:
    """Legge il raw applica la normalizzazione canonica e salva il risultato"""

    settings = get_settings()

    logger.info("inizio normalize to canonical")

    with get_connection(settings) as conn:
        with conn.transaction():
            urlhaus_summary = _process_urlhaus(conn)
            threatfox_summary = _process_threatfox(conn)

    total_summary = {
        "raw_urlhaus_rows": urlhaus_summary["raw_rows"],
        "urlhaus_normalized_rows": urlhaus_summary["normalized_rows"],
        "urlhaus_deduplicated_rows": urlhaus_summary["deduplicated_rows"],
        "urlhaus_upserted_rows": urlhaus_summary["upserted_rows"],
        "raw_threatfox_rows": threatfox_summary["raw_rows"],
        "threatfox_normalized_rows": threatfox_summary["normalized_rows"],
        "threatfox_deduplicated_rows": threatfox_summary["deduplicated_rows"],
        "threatfox_upserted_rows": threatfox_summary["upserted_rows"],
    }

    logger.info("fine normalize to canonical summary=%s", total_summary)

    print("normalizzazione canonica completata")
    print(f"raw urlhaus letti: {total_summary['raw_urlhaus_rows']}")
    print(f"urlhaus normalizzati validi: {total_summary['urlhaus_normalized_rows']}")
    print(f"urlhaus deduplicati: {total_summary['urlhaus_deduplicated_rows']}")
    print(f"urlhaus upsertati: {total_summary['urlhaus_upserted_rows']}")
    print(f"raw threatfox letti: {total_summary['raw_threatfox_rows']}")
    print(f"threatfox normalizzati validi: {total_summary['threatfox_normalized_rows']}")
    print(f"threatfox deduplicati: {total_summary['threatfox_deduplicated_rows']}")
    print(f"threatfox upsertati: {total_summary['threatfox_upserted_rows']}")


def _process_urlhaus(conn: psycopg.Connection) -> dict[str, int]:
    """Esegue fetch normalizzazione deduplica e upsert per URLhaus"""

    raw_rows = _fetch_raw_rows(conn, "raw_urlhaus")
    normalized_rows = normalize_urlhaus_rows(raw_rows)
    deduplicated_rows = deduplicate_canonical_rows(normalized_rows)
    upserted_rows = _upsert_canonical_rows(conn, deduplicated_rows)

    summary = {
        "raw_rows": len(raw_rows),
        "normalized_rows": len(normalized_rows),
        "deduplicated_rows": len(deduplicated_rows),
        "upserted_rows": upserted_rows,
    }

    logger.info("urlhaus summary=%s", summary)
    return summary


def _process_threatfox(conn: psycopg.Connection) -> dict[str, int]:
    """Esegue fetch normalizzazione deduplica e upsert per ThreatFox"""

    raw_rows = _fetch_raw_rows(conn, "raw_threatfox")
    normalized_rows = normalize_threatfox_rows(raw_rows)
    deduplicated_rows = deduplicate_canonical_rows(normalized_rows)
    upserted_rows = _upsert_canonical_rows(conn, deduplicated_rows)

    summary = {
        "raw_rows": len(raw_rows),
        "normalized_rows": len(normalized_rows),
        "deduplicated_rows": len(deduplicated_rows),
        "upserted_rows": upserted_rows,
    }

    logger.info("threatfox summary=%s", summary)
    return summary


def _fetch_raw_rows(
    conn: psycopg.Connection,
    table_name: str,
) -> list[dict]:
    """Legge le righe raw minime necessarie alla normalizzazione canonica"""

    if table_name not in {"raw_urlhaus", "raw_threatfox"}:
        raise ValueError(f"tabella raw non ammessa: {table_name}")

    sql = f"""
        select
            raw_id,
            source_record_id,
            payload_json
        from {table_name}
        order by raw_id
    """

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql)
        rows = cur.fetchall()

    return [dict(row) for row in rows]


def _upsert_canonical_rows(
    conn: psycopg.Connection,
    rows: list[dict],
) -> int:
    """Esegue l upsert dei record canonici nella tabella intermedia"""

    if not rows:
        return 0

    sql = """
        insert into canonical_observation (
            source_name,
            raw_table_name,
            raw_id,
            source_record_id,
            indicator_type,
            indicator_value,
            event_time,
            day_bucket,
            status,
            tags,
            context_json
        )
        values (
            %(source_name)s,
            %(raw_table_name)s,
            %(raw_id)s,
            %(source_record_id)s,
            %(indicator_type)s,
            %(indicator_value)s,
            %(event_time)s,
            %(day_bucket)s,
            %(status)s,
            %(tags)s,
            %(context_json)s
        )
        on conflict (
            source_name,
            indicator_type,
            indicator_value,
            day_bucket
        )
        do update
        set
            raw_table_name = excluded.raw_table_name,
            raw_id = excluded.raw_id,
            source_record_id = excluded.source_record_id,
            event_time = excluded.event_time,
            status = excluded.status,
            tags = excluded.tags,
            context_json = excluded.context_json
    """

    prepared_rows = []

    #preparazione righe per jsonb
    for row in rows:
        prepared_rows.append(
            {
                "source_name": row["source_name"],
                "raw_table_name": row["raw_table_name"],
                "raw_id": row["raw_id"],
                "source_record_id": row.get("source_record_id"),
                "indicator_type": row["indicator_type"],
                "indicator_value": row["indicator_value"],
                "event_time": row["event_time"],
                "day_bucket": row["day_bucket"],
                "status": row["status"],
                "tags": row["tags"],
                "context_json": Jsonb(row["context_json"]) if row.get("context_json") is not None else None,
            }
        )

    with conn.cursor() as cur:
        cur.executemany(sql, prepared_rows)

    return len(prepared_rows)


if __name__ == "__main__":
    main()