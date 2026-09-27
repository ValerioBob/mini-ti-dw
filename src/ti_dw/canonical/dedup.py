from __future__ import annotations

from typing import Any


def deduplicate_canonical_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplica i record canonici e tiene il raw_id più alto per chiave logica"""

    best_rows: dict[tuple[Any, ...], dict[str, Any]] = {}

    #selezione del record vincente per chiave logica
    for row in rows:
        dedup_key = _build_dedup_key(row)
        current_row = best_rows.get(dedup_key)

        if current_row is None:
            best_rows[dedup_key] = row
            continue

        best_rows[dedup_key] = _choose_preferred_row(current_row, row)

    return sorted(best_rows.values(), key=lambda row: row["raw_id"])


def _build_dedup_key(row: dict[str, Any]) -> tuple[Any, ...]:
    """Costruisce la chiave logica di deduplica del layer canonico"""

    return (
        row["source_name"],
        row["indicator_type"],
        row["indicator_value"],
        row["day_bucket"],
    )


def _choose_preferred_row(
    current_row: dict[str, Any],
    candidate_row: dict[str, Any],
) -> dict[str, Any]:
    """Confronta due record omologhi e restituisce quello preferito"""

    if candidate_row["raw_id"] >= current_row["raw_id"]:
        return candidate_row

    return current_row