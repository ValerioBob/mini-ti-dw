import unittest
from datetime import date, datetime

from ti_dw.canonical.normalize import (
    normalize_threatfox_rows,
    normalize_urlhaus_rows,
)


class TestNormalizeUrlhaus(unittest.TestCase):
    """Verifica la normalizzazione dei record URLhaus"""

    def test_normalize_urlhaus_valid_row(self) -> None:
        """Normalizza correttamente una riga URLhaus valida"""

        raw_rows = [
            {
                "raw_id": 1,
                "source_record_id": "3793420",
                "payload_json": {
                    "id": "3793420",
                    "url": "https://sili-h7.siliconcanyon.in.net/verification.google",
                    "tags": "ClearFake",
                    "threat": "malware_download",
                    "reporter": "anonymous",
                    "dateadded": "2026-03-10 07:15:18",
                    "url_status": "online",
                    "last_online": "2026-03-10 07:15:18",
                    "urlhaus_link": "https://urlhaus.abuse.ch/url/3793420/",
                },
            }
        ]

        rows = normalize_urlhaus_rows(raw_rows)

        self.assertEqual(len(rows), 1)

        row = rows[0]
        self.assertEqual(row["source_name"], "urlhaus")
        self.assertEqual(row["raw_table_name"], "raw_urlhaus")
        self.assertEqual(row["raw_id"], 1)
        self.assertEqual(row["source_record_id"], "3793420")
        self.assertEqual(row["indicator_type"], "url")
        self.assertEqual(
            row["indicator_value"],
            "https://sili-h7.siliconcanyon.in.net/verification.google",
        )
        self.assertEqual(row["event_time"], datetime(2026, 3, 10, 7, 15, 18))
        self.assertEqual(row["day_bucket"], date(2026, 3, 10))
        self.assertEqual(row["status"], "online")
        self.assertEqual(row["tags"], ["ClearFake"])
        self.assertEqual(row["context_json"]["threat"], "malware_download")
        self.assertEqual(row["context_json"]["reporter"], "anonymous")

    def test_normalize_urlhaus_invalid_date(self) -> None:
        """Scarta una riga URLhaus con data non valida"""

        raw_rows = [
            {
                "raw_id": 1,
                "source_record_id": "3793420",
                "payload_json": {
                    "url": "https://example.test/a",
                    "dateadded": "2026/03/10 07:15:18",
                    "url_status": "online",
                },
            }
        ]

        rows = normalize_urlhaus_rows(raw_rows)
        self.assertEqual(rows, [])

    def test_normalize_urlhaus_tags_deduplicated(self) -> None:
        """Deduplica i tag URLhaus mantenendo l ordine"""

        raw_rows = [
            {
                "raw_id": 1,
                "source_record_id": "1",
                "payload_json": {
                    "url": "https://example.test/a",
                    "dateadded": "2026-03-10 07:15:18",
                    "url_status": "offline",
                    "tags": " ClearFake, Test, ClearFake ,  ",
                },
            }
        ]

        rows = normalize_urlhaus_rows(raw_rows)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["tags"], ["ClearFake", "Test"])
        self.assertEqual(rows[0]["status"], "offline")


class TestNormalizeThreatfox(unittest.TestCase):
    """Verifica la normalizzazione dei record ThreatFox"""

    def test_normalize_threatfox_domain_row(self) -> None:
        """Normalizza correttamente una riga ThreatFox di tipo domain"""

        raw_rows = [
            {
                "raw_id": 1,
                "source_record_id": "1762588",
                "payload_json": {
                    "id": "1762588",
                    "ioc": "unit-r1.siliconcanyon.in.net",
                    "tags": ["ClearFake"],
                    "malware": "js.clearfake",
                    "ioc_type": "domain",
                    "reporter": "threatcat_ch",
                    "last_seen": "2026-03-10 07:20:40 UTC",
                    "reference": None,
                    "first_seen": "2026-03-10 07:19:39 UTC",
                    "threat_type": "payload_delivery",
                    "ioc_type_desc": "Domain name that delivers a malware payload",
                    "malware_alias": None,
                    "is_compromised": False,
                    "confidence_level": 100,
                    "malware_malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/js.clearfake",
                    "threat_type_desc": "Indicator that identifies a malware distribution server",
                    "malware_printable": "ClearFake",
                },
            }
        ]

        rows = normalize_threatfox_rows(raw_rows)

        self.assertEqual(len(rows), 1)

        row = rows[0]
        self.assertEqual(row["source_name"], "threatfox")
        self.assertEqual(row["raw_table_name"], "raw_threatfox")
        self.assertEqual(row["raw_id"], 1)
        self.assertEqual(row["source_record_id"], "1762588")
        self.assertEqual(row["indicator_type"], "domain")
        self.assertEqual(row["indicator_value"], "unit-r1.siliconcanyon.in.net")
        self.assertEqual(row["event_time"], datetime(2026, 3, 10, 7, 19, 39))
        self.assertEqual(row["day_bucket"], date(2026, 3, 10))
        self.assertEqual(row["status"], "unknown")
        self.assertEqual(row["tags"], ["ClearFake"])
        self.assertEqual(row["context_json"]["malware"], "js.clearfake")
        self.assertEqual(row["context_json"]["reporter"], "threatcat_ch")
        self.assertEqual(row["context_json"]["confidence_level"], 100)

    def test_normalize_threatfox_ip_port_ipv4(self) -> None:
        """Riduce ip porta al solo ip e salva la porta nel contesto"""

        raw_rows = [
            {
                "raw_id": 2,
                "source_record_id": "2",
                "payload_json": {
                    "id": "2",
                    "ioc": "45.156.87.17:443",
                    "tags": ["ClearFake", "ClearFake"],
                    "ioc_type": "ip:port",
                    "first_seen": "2026-03-10 07:19:39 UTC",
                },
            }
        ]

        rows = normalize_threatfox_rows(raw_rows)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["indicator_type"], "ip")
        self.assertEqual(rows[0]["indicator_value"], "45.156.87.17")
        self.assertEqual(rows[0]["tags"], ["ClearFake"])
        self.assertEqual(rows[0]["context_json"]["port"], "443")

    def test_normalize_threatfox_ip_port_ipv6(self) -> None:
        """Riduce ipv6 porta al solo ip e salva la porta nel contesto"""

        raw_rows = [
            {
                "raw_id": 3,
                "source_record_id": "3",
                "payload_json": {
                    "id": "3",
                    "ioc": "[2001:db8::10]:8443",
                    "tags": [],
                    "ioc_type": "ip:port",
                    "first_seen": "2026-03-10 07:19:39 UTC",
                },
            }
        ]

        rows = normalize_threatfox_rows(raw_rows)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["indicator_type"], "ip")
        self.assertEqual(rows[0]["indicator_value"], "2001:db8::10")
        self.assertEqual(rows[0]["context_json"]["port"], "8443")

    def test_normalize_threatfox_invalid_first_seen(self) -> None:
        """Scarta una riga ThreatFox con first_seen non valido"""

        raw_rows = [
            {
                "raw_id": 1,
                "source_record_id": "1",
                "payload_json": {
                    "ioc": "example.test",
                    "ioc_type": "domain",
                    "first_seen": "2026-03-10T07:19:39Z",
                },
            }
        ]

        rows = normalize_threatfox_rows(raw_rows)
        self.assertEqual(rows, [])

    def test_normalize_threatfox_out_of_scope_type(self) -> None:
        """Scarta i tipi IOC fuori scope"""

        raw_rows = [
            {
                "raw_id": 1,
                "source_record_id": "1",
                "payload_json": {
                    "ioc": "abc123",
                    "ioc_type": "md5_hash",
                    "first_seen": "2026-03-10 07:19:39 UTC",
                },
            }
        ]

        rows = normalize_threatfox_rows(raw_rows)
        self.assertEqual(rows, [])

    def test_normalize_threatfox_domain_lowercase(self) -> None:
        """Porta i domain ThreatFox in lower case"""

        raw_rows = [
            {
                "raw_id": 1,
                "source_record_id": "1",
                "payload_json": {
                    "ioc": "Unit-R1.SiliconCanyon.IN.NET.",
                    "ioc_type": "domain",
                    "first_seen": "2026-03-10 07:19:39 UTC",
                },
            }
        ]

        rows = normalize_threatfox_rows(raw_rows)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["indicator_value"], "unit-r1.siliconcanyon.in.net")


if __name__ == "__main__":
    unittest.main()