from __future__ import annotations

import ipaddress
from datetime import date
from urllib.parse import urlsplit

import psycopg
from psycopg.rows import dict_row

from ti_dw.config import get_settings
from ti_dw.db import get_connection
from ti_dw.logging import get_logger


logger = get_logger(__name__)

_ALLOWED_COUNT_TABLES = {
    "dim_time",
    "dim_indicator",
    "dim_tag",
    "fact_observation",
    "bridge_observation_tag",
}

_MONTH_NAMES = {
    1: "January",
    2: "February",
    3: "March",
    4: "April",
    5: "May",
    6: "June",
    7: "July",
    8: "August",
    9: "September",
    10: "October",
    11: "November",
    12: "December",
}


def load_dw() -> dict[str, int]:
    """Carica il dw dal layer canonico e restituisce un riepilogo numerico"""

    settings = get_settings()

    logger.info("inizio load dw")

    with get_connection(settings) as conn:
        with conn.transaction():
            _ensure_static_dimensions(conn)

            canonical_rows = _fetch_canonical_rows(conn)
            logger.info("record canonici letti=%s", len(canonical_rows))

            if not canonical_rows:
                summary = {
                    "canonical_rows": 0,
                    "dim_time_new_rows": 0,
                    "dim_indicator_new_rows": 0,
                    "dim_tag_new_rows": 0,
                    "fact_observation_new_rows": 0,
                    "bridge_observation_tag_new_rows": 0,
                }

                logger.info("nessun record canonico trovato")
                return summary

            source_map = _fetch_lookup_map(
                conn,
                table_name="dim_source",
                id_column="source_id",
                value_column="source_name",
            )
            indicator_type_map = _fetch_lookup_map(
                conn,
                table_name="dim_indicator_type",
                id_column="indicator_type_id",
                value_column="indicator_type_name",
            )
            status_map = _fetch_lookup_map(
                conn,
                table_name="dim_status",
                id_column="status_id",
                value_column="status_name",
            )

            _validate_static_dimensions(
                source_map=source_map,
                indicator_type_map=indicator_type_map,
                status_map=status_map,
            )

            dim_time_new_rows = _load_dim_time(conn, canonical_rows)
            time_map = _fetch_time_map(conn)

            dim_indicator_new_rows = _load_dim_indicator(
                conn,
                canonical_rows=canonical_rows,
                indicator_type_map=indicator_type_map,
            )
            indicator_map = _fetch_indicator_map(conn)

            dim_tag_new_rows = _load_dim_tag(conn, canonical_rows)
            tag_map = _fetch_tag_map(conn)

            fact_observation_new_rows = _load_fact_observation(
                conn,
                canonical_rows=canonical_rows,
                source_map=source_map,
                indicator_type_map=indicator_type_map,
                status_map=status_map,
                time_map=time_map,
                indicator_map=indicator_map,
            )

            observation_map = _fetch_observation_map(conn)

            bridge_observation_tag_new_rows = _load_bridge_observation_tag(
                conn,
                canonical_rows=canonical_rows,
                observation_map=observation_map,
                tag_map=tag_map,
            )

    summary = {
        "canonical_rows": len(canonical_rows),
        "dim_time_new_rows": dim_time_new_rows,
        "dim_indicator_new_rows": dim_indicator_new_rows,
        "dim_tag_new_rows": dim_tag_new_rows,
        "fact_observation_new_rows": fact_observation_new_rows,
        "bridge_observation_tag_new_rows": bridge_observation_tag_new_rows,
    }

    logger.info("fine load dw summary=%s", summary)
    return summary


def _ensure_static_dimensions(conn: psycopg.Connection) -> None:
    """Assicura la presenza dei dizionari statici minimi del dw"""

    with conn.cursor() as cur:
        cur.execute(
            """
            insert into dim_source (source_name)
            values
                ('urlhaus'),
                ('threatfox')
            on conflict (source_name) do nothing
            """
        )

        cur.execute(
            """
            insert into dim_indicator_type (indicator_type_name)
            values
                ('url'),
                ('domain'),
                ('ip')
            on conflict (indicator_type_name) do nothing
            """
        )

        cur.execute(
            """
            insert into dim_status (status_name)
            values
                ('online'),
                ('offline'),
                ('unknown')
            on conflict (status_name) do nothing
            """
        )


def _fetch_canonical_rows(conn: psycopg.Connection) -> list[dict]:
    """Legge i record canonici necessari al caricamento del dw"""

    sql = """
        select
            canonical_id,
            source_name,
            indicator_type,
            indicator_value,
            day_bucket,
            status,
            tags
        from canonical_observation
        order by canonical_id
    """

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql)
        rows = cur.fetchall()

    return [dict(row) for row in rows]


def _load_dim_time(
    conn: psycopg.Connection,
    canonical_rows: list[dict],
) -> int:
    """Popola la dimensione tempo partendo dai day bucket canonici"""

    before_count = _count_rows(conn, "dim_time")

    distinct_days = sorted({row["day_bucket"] for row in canonical_rows})
    rows_to_insert = []

    #costruzione dei record temporali
    for day_value in distinct_days:
        rows_to_insert.append(
            {
                "time_id": _build_time_id(day_value),
                "day_date": day_value,
                "day_of_month": day_value.day,
                "month_num": day_value.month,
                "month_name": _MONTH_NAMES[day_value.month],
                "quarter_num": ((day_value.month - 1) // 3) + 1,
                "year_num": day_value.year,
            }
        )

    if not rows_to_insert:
        return 0

    sql = """
        insert into dim_time (
            time_id,
            day_date,
            day_of_month,
            month_num,
            month_name,
            quarter_num,
            year_num
        )
        values (
            %(time_id)s,
            %(day_date)s,
            %(day_of_month)s,
            %(month_num)s,
            %(month_name)s,
            %(quarter_num)s,
            %(year_num)s
        )
        on conflict (time_id) do nothing
    """

    with conn.cursor() as cur:
        cur.executemany(sql, rows_to_insert)

    after_count = _count_rows(conn, "dim_time")
    return after_count - before_count


def _load_dim_indicator(
    conn: psycopg.Connection,
    canonical_rows: list[dict],
    indicator_type_map: dict[str, int],
) -> int:
    """Popola la dimensione indicatore derivando dominio e tld quando possibile"""

    before_count = _count_rows(conn, "dim_indicator")

    unique_rows: dict[tuple[int, str], dict] = {}

    #deduplica tecnica lato loader
    for row in canonical_rows:
        indicator_type_id = indicator_type_map[row["indicator_type"]]
        indicator_value = row["indicator_value"]

        key = (indicator_type_id, indicator_value)
        if key in unique_rows:
            continue

        domain_value, tld = _derive_domain_and_tld(
            indicator_type=row["indicator_type"],
            indicator_value=indicator_value,
        )

        unique_rows[key] = {
            "indicator_type_id": indicator_type_id,
            "indicator_value": indicator_value,
            "domain_value": domain_value,
            "tld": tld,
        }

    rows_to_insert = list(unique_rows.values())

    if not rows_to_insert:
        return 0

    sql = """
        insert into dim_indicator (
            indicator_type_id,
            indicator_value,
            domain_value,
            tld
        )
        values (
            %(indicator_type_id)s,
            %(indicator_value)s,
            %(domain_value)s,
            %(tld)s
        )
        on conflict (indicator_type_id, indicator_value)
        do update
        set
            domain_value = coalesce(excluded.domain_value, dim_indicator.domain_value),
            tld = coalesce(excluded.tld, dim_indicator.tld)
    """

    with conn.cursor() as cur:
        cur.executemany(sql, rows_to_insert)

    after_count = _count_rows(conn, "dim_indicator")
    return after_count - before_count


def _load_dim_tag(
    conn: psycopg.Connection,
    canonical_rows: list[dict],
) -> int:
    """Popola il dizionario dei tag leggendo gli array presenti nel canonico"""

    before_count = _count_rows(conn, "dim_tag")

    tag_names = set()

    #raccolta dei tag distinti
    for row in canonical_rows:
        for tag_name in row["tags"] or []:
            clean_tag = tag_name.strip()
            if clean_tag:
                tag_names.add(clean_tag)

    rows_to_insert = [{"tag_name": tag_name} for tag_name in sorted(tag_names)]

    if not rows_to_insert:
        return 0

    sql = """
        insert into dim_tag (tag_name)
        values (%(tag_name)s)
        on conflict (tag_name) do nothing
    """

    with conn.cursor() as cur:
        cur.executemany(sql, rows_to_insert)

    after_count = _count_rows(conn, "dim_tag")
    return after_count - before_count


def _load_fact_observation(
    conn: psycopg.Connection,
    canonical_rows: list[dict],
    source_map: dict[str, int],
    indicator_type_map: dict[str, int],
    status_map: dict[str, int],
    time_map: dict[date, int],
    indicator_map: dict[tuple[int, str], int],
) -> int:
    """Carica la fact principale usando canonical_id come chiave di idempotenza"""

    before_count = _count_rows(conn, "fact_observation")

    rows_to_upsert = []

    #costruzione dei fatti
    for row in canonical_rows:
        indicator_type_id = indicator_type_map[row["indicator_type"]]

        rows_to_upsert.append(
            {
                "canonical_id": row["canonical_id"],
                "time_id": time_map[row["day_bucket"]],
                "source_id": source_map[row["source_name"]],
                "indicator_type_id": indicator_type_id,
                "indicator_id": indicator_map[(indicator_type_id, row["indicator_value"])],
                "status_id": status_map[row["status"]],
                "obs_count": 1,
                "is_online": _status_to_is_online(row["status"]),
            }
        )

    if not rows_to_upsert:
        return 0

    sql = """
        insert into fact_observation (
            canonical_id,
            time_id,
            source_id,
            indicator_type_id,
            indicator_id,
            status_id,
            obs_count,
            is_online
        )
        values (
            %(canonical_id)s,
            %(time_id)s,
            %(source_id)s,
            %(indicator_type_id)s,
            %(indicator_id)s,
            %(status_id)s,
            %(obs_count)s,
            %(is_online)s
        )
        on conflict (canonical_id)
        do update
        set
            time_id = excluded.time_id,
            source_id = excluded.source_id,
            indicator_type_id = excluded.indicator_type_id,
            indicator_id = excluded.indicator_id,
            status_id = excluded.status_id,
            obs_count = excluded.obs_count,
            is_online = excluded.is_online
    """

    with conn.cursor() as cur:
        cur.executemany(sql, rows_to_upsert)

    after_count = _count_rows(conn, "fact_observation")
    return after_count - before_count


def _load_bridge_observation_tag(
    conn: psycopg.Connection,
    canonical_rows: list[dict],
    observation_map: dict[int, int],
    tag_map: dict[str, int],
) -> int:
    """Carica la bridge tra osservazioni e tag"""

    before_count = _count_rows(conn, "bridge_observation_tag")

    bridge_pairs = set()

    #espansione dei tag associati a ogni osservazione
    for row in canonical_rows:
        observation_id = observation_map.get(row["canonical_id"])
        if observation_id is None:
            continue

        for tag_name in row["tags"] or []:
            clean_tag = tag_name.strip()
            if not clean_tag:
                continue

            tag_id = tag_map.get(clean_tag)
            if tag_id is None:
                continue

            bridge_pairs.add((observation_id, tag_id))

    rows_to_insert = [
        {
            "observation_id": observation_id,
            "tag_id": tag_id,
        }
        for observation_id, tag_id in sorted(bridge_pairs)
    ]

    if not rows_to_insert:
        return 0

    sql = """
        insert into bridge_observation_tag (
            observation_id,
            tag_id
        )
        values (
            %(observation_id)s,
            %(tag_id)s
        )
        on conflict do nothing
    """

    with conn.cursor() as cur:
        cur.executemany(sql, rows_to_insert)

    after_count = _count_rows(conn, "bridge_observation_tag")
    return after_count - before_count


def _fetch_lookup_map(
    conn: psycopg.Connection,
    table_name: str,
    id_column: str,
    value_column: str,
) -> dict[str, int]:
    """Legge una piccola dimensione di lookup e restituisce una mappa valore id"""

    sql = f"""
        select
            {id_column},
            {value_column}
        from {table_name}
    """

    with conn.cursor() as cur:
        cur.execute(sql)
        rows = cur.fetchall()

    return {value: record_id for record_id, value in rows}


def _fetch_time_map(conn: psycopg.Connection) -> dict[date, int]:
    """Legge la mappa data chiave della dimensione tempo"""

    with conn.cursor() as cur:
        cur.execute(
            """
            select
                time_id,
                day_date
            from dim_time
            """
        )
        rows = cur.fetchall()

    return {day_date: time_id for time_id, day_date in rows}


def _fetch_indicator_map(conn: psycopg.Connection) -> dict[tuple[int, str], int]:
    """Legge la mappa tipo valore chiave della dimensione indicatore"""

    with conn.cursor() as cur:
        cur.execute(
            """
            select
                indicator_id,
                indicator_type_id,
                indicator_value
            from dim_indicator
            """
        )
        rows = cur.fetchall()

    return {
        (indicator_type_id, indicator_value): indicator_id
        for indicator_id, indicator_type_id, indicator_value in rows
    }


def _fetch_tag_map(conn: psycopg.Connection) -> dict[str, int]:
    """Legge la mappa nome chiave della dimensione tag"""

    with conn.cursor() as cur:
        cur.execute(
            """
            select
                tag_id,
                tag_name
            from dim_tag
            """
        )
        rows = cur.fetchall()

    return {tag_name: tag_id for tag_id, tag_name in rows}


def _fetch_observation_map(conn: psycopg.Connection) -> dict[int, int]:
    """Legge la mappa canonical_id observation_id della fact"""

    with conn.cursor() as cur:
        cur.execute(
            """
            select
                observation_id,
                canonical_id
            from fact_observation
            """
        )
        rows = cur.fetchall()

    return {canonical_id: observation_id for observation_id, canonical_id in rows}


def _validate_static_dimensions(
    source_map: dict[str, int],
    indicator_type_map: dict[str, int],
    status_map: dict[str, int],
) -> None:
    """Controlla che i dizionari statici minimi siano disponibili"""

    required_sources = {"urlhaus", "threatfox"}
    required_indicator_types = {"url", "domain", "ip"}
    required_statuses = {"online", "offline", "unknown"}

    if not required_sources.issubset(source_map):
        raise RuntimeError("dim_source incompleta")

    if not required_indicator_types.issubset(indicator_type_map):
        raise RuntimeError("dim_indicator_type incompleta")

    if not required_statuses.issubset(status_map):
        raise RuntimeError("dim_status incompleta")


def _count_rows(conn: psycopg.Connection, table_name: str) -> int:
    """Conta le righe di una tabella del dw ammessa internamente"""

    if table_name not in _ALLOWED_COUNT_TABLES:
        raise ValueError(f"tabella non ammessa per il count: {table_name}")

    sql = f"select count(*) from {table_name}"

    with conn.cursor() as cur:
        cur.execute(sql)
        row_count = cur.fetchone()[0]

    return int(row_count)


def _build_time_id(day_value: date) -> int:
    """Converte una data nel formato intero yyyymmdd"""

    return int(day_value.strftime("%Y%m%d"))


def _status_to_is_online(status: str) -> bool | None:
    """Converte lo stato canonico nella misura booleana del dw"""

    if status == "online":
        return True

    if status == "offline":
        return False

    return None


def _derive_domain_and_tld(
    indicator_type: str,
    indicator_value: str,
) -> tuple[str | None, str | None]:
    """Deriva dominio e tld con logica prudente dal tipo e valore indicatore"""

    if indicator_type == "ip":
        return None, None

    if indicator_type == "domain":
        domain_value = _normalize_host(indicator_value)
        if not domain_value or _is_ip_address(domain_value):
            return None, None

        return domain_value, _extract_tld(domain_value)

    if indicator_type == "url":
        host_value = _extract_host_from_url(indicator_value)
        if not host_value or _is_ip_address(host_value):
            return None, None

        return host_value, _extract_tld(host_value)

    return None, None


def _extract_host_from_url(url_value: str) -> str | None:
    """Estrae l host da una url con fallback per valori senza schema"""

    candidate = url_value.strip()
    if not candidate:
        return None

    #tentativo standard
    parsed = urlsplit(candidate)
    host_value = parsed.hostname

    #fallback prudente per valori tipo host o host path
    if not host_value and "://" not in candidate:
        parsed = urlsplit(f"//{candidate}")
        host_value = parsed.hostname

    return _normalize_host(host_value)


def _normalize_host(host_value: str | None) -> str | None:
    """Normalizza in modo leggero un host o dominio"""

    if host_value is None:
        return None

    clean_value = host_value.strip().lower().rstrip(".")
    return clean_value or None


def _extract_tld(host_value: str) -> str | None:
    """Estrae l ultima label di un host se sembra un dominio"""

    if "." not in host_value:
        return None

    labels = [label for label in host_value.split(".") if label]
    if len(labels) < 2:
        return None

    return labels[-1].lower()


def _is_ip_address(value: str) -> bool:
    """Verifica se una stringa rappresenta un indirizzo ip valido"""

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False