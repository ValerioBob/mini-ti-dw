import unittest
from datetime import date, datetime

from ti_dw.canonical.dedup import deduplicate_canonical_rows


class TestDedupCanonical(unittest.TestCase):
    """Verifica la deduplica del layer canonico"""

    def test_keep_row_with_highest_raw_id(self) -> None:
        """Tiene il record con raw_id più alto sulla stessa chiave logica"""

        rows = [
            {
                "source_name": "threatfox",
                "raw_table_name": "raw_threatfox",
                "raw_id": 10,
                "source_record_id": "100",
                "indicator_type": "domain",
                "indicator_value": "example.test",
                "event_time": datetime(2026, 3, 10, 7, 10, 0),
                "day_bucket": date(2026, 3, 10),
                "status": "unknown",
                "tags": ["a"],
                "context_json": {"port": None},
            },
            {
                "source_name": "threatfox",
                "raw_table_name": "raw_threatfox",
                "raw_id": 11,
                "source_record_id": "101",
                "indicator_type": "domain",
                "indicator_value": "example.test",
                "event_time": datetime(2026, 3, 10, 7, 11, 0),
                "day_bucket": date(2026, 3, 10),
                "status": "unknown",
                "tags": ["b"],
                "context_json": {"port": "443"},
            },
        ]

        result = deduplicate_canonical_rows(rows)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["raw_id"], 11)
        self.assertEqual(result[0]["source_record_id"], "101")

    def test_keep_rows_for_different_days(self) -> None:
        """Non deduplica record con stesso indicatore in giorni diversi"""

        rows = [
            {
                "source_name": "urlhaus",
                "raw_table_name": "raw_urlhaus",
                "raw_id": 1,
                "source_record_id": "1",
                "indicator_type": "url",
                "indicator_value": "https://example.test/a",
                "event_time": datetime(2026, 3, 10, 7, 10, 0),
                "day_bucket": date(2026, 3, 10),
                "status": "online",
                "tags": [],
                "context_json": None,
            },
            {
                "source_name": "urlhaus",
                "raw_table_name": "raw_urlhaus",
                "raw_id": 2,
                "source_record_id": "2",
                "indicator_type": "url",
                "indicator_value": "https://example.test/a",
                "event_time": datetime(2026, 3, 11, 7, 10, 0),
                "day_bucket": date(2026, 3, 11),
                "status": "offline",
                "tags": [],
                "context_json": None,
            },
        ]

        result = deduplicate_canonical_rows(rows)

        self.assertEqual(len(result), 2)

    def test_keep_rows_for_different_sources(self) -> None:
        """Non deduplica record uguali ma provenienti da sorgenti diverse"""

        rows = [
            {
                "source_name": "urlhaus",
                "raw_table_name": "raw_urlhaus",
                "raw_id": 1,
                "source_record_id": "1",
                "indicator_type": "url",
                "indicator_value": "https://example.test/a",
                "event_time": datetime(2026, 3, 10, 7, 10, 0),
                "day_bucket": date(2026, 3, 10),
                "status": "online",
                "tags": [],
                "context_json": None,
            },
            {
                "source_name": "threatfox",
                "raw_table_name": "raw_threatfox",
                "raw_id": 2,
                "source_record_id": "2",
                "indicator_type": "url",
                "indicator_value": "https://example.test/a",
                "event_time": datetime(2026, 3, 10, 7, 10, 0),
                "day_bucket": date(2026, 3, 10),
                "status": "unknown",
                "tags": [],
                "context_json": None,
            },
        ]

        result = deduplicate_canonical_rows(rows)

        self.assertEqual(len(result), 2)


if __name__ == "__main__":
    unittest.main()