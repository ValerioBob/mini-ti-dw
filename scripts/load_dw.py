from __future__ import annotations

from ti_dw.warehouse.load import load_dw


def main() -> None:
    """Esegue il caricamento del dw dal layer canonico"""

    summary = load_dw()

    print("caricamento dw completato")
    print(f"record canonici letti: {summary['canonical_rows']}")
    print(f"nuove righe dim_time: {summary['dim_time_new_rows']}")
    print(f"nuove righe dim_indicator: {summary['dim_indicator_new_rows']}")
    print(f"nuove righe dim_tag: {summary['dim_tag_new_rows']}")
    print(f"nuove righe fact_observation: {summary['fact_observation_new_rows']}")
    print(
        "nuove righe bridge_observation_tag: "
        f"{summary['bridge_observation_tag_new_rows']}"
    )


if __name__ == "__main__":
    main()