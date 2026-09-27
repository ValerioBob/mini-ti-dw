from __future__ import annotations

import argparse
from datetime import date

from ti_dw.raw.ingest import ingest_urlhaus


def main() -> None:
    """Esegue l ingest raw di URLhaus da riga di comando"""

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--snapshot-date",
        type=date.fromisoformat,
        help="data logica dello snapshot in formato YYYY-MM-DD",
    )
    args = parser.parse_args()

    inserted = ingest_urlhaus(snapshot_date=args.snapshot_date)
    print(f"record inseriti in raw_urlhaus: {inserted}")


if __name__ == "__main__":
    main()