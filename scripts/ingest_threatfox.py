from __future__ import annotations

import argparse
from datetime import date

from ti_dw.raw.ingest import ingest_threatfox


def main() -> None:
    """Esegue l ingest raw di ThreatFox da riga di comando"""

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--days",
        type=int,
        default=1,
        help="numero di giorni recenti da richiedere a ThreatFox",
    )
    parser.add_argument(
        "--snapshot-date",
        type=date.fromisoformat,
        help="data logica dello snapshot in formato YYYY-MM-DD",
    )
    args = parser.parse_args()

    inserted = ingest_threatfox(
        days=args.days,
        snapshot_date=args.snapshot_date,
    )
    print(f"record inseriti in raw_threatfox: {inserted}")


if __name__ == "__main__":
    main()