from __future__ import annotations

from typing import Iterable

import psycopg
from psycopg.types.json import Jsonb

from ti_dw.config import Settings


_ALLOWED_RAW_TABLES = {
    "raw_urlhaus",
    "raw_threatfox",
}


def get_connection(settings: Settings) -> psycopg.Connection:
    """Apre una connessione PostgreSQL usando la configurazione presa da env"""

    return psycopg.connect(settings.database_url)


def insert_raw_records(
    conn: psycopg.Connection,
    table_name: str,
    rows: Iterable[dict],
) -> int:
    """Inserisce una sequenza di record nella tabella raw richiesta"""

    if table_name not in _ALLOWED_RAW_TABLES:
        raise ValueError(f"tabella raw non ammessa: {table_name}")

    sql = f"""
        insert into {table_name} (
            ingest_batch_id,
            snapshot_date,
            source_record_id,
            payload_json,
            trace_meta
        )
        values (
            %(ingest_batch_id)s,
            %(snapshot_date)s,
            %(source_record_id)s,
            %(payload_json)s,
            %(trace_meta)s
        )
    """

    prepared_rows = []

    for row in rows:
        prepared_rows.append(
            {
                "ingest_batch_id": row["ingest_batch_id"],
                "snapshot_date": row["snapshot_date"],
                "source_record_id": row.get("source_record_id"),
                "payload_json": Jsonb(row["payload_json"]),
                "trace_meta": Jsonb(row.get("trace_meta") or {}),
            }
        )

    if not prepared_rows:
        return 0

    with conn.cursor() as cur:
        cur.executemany(sql, prepared_rows)

    return len(prepared_rows)