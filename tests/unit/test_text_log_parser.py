import unittest, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.ingestion.text_log_parser import text_to_compact_csv
from backend.preprocessing.log_processor import LogProcessor


class TestTextLogParser(unittest.TestCase):
    def test_kv_line_conversion(self):
        raw = "duration=2 protocol=tcp service=http flag=SF src_bytes=1200 dst_bytes=400 label=neptune"
        out = text_to_compact_csv(raw)
        self.assertEqual(out, "2,tcp,http,SF,1200,400,0,0,0,neptune")

    def test_mixed_text_parses_protocol_and_bytes(self):
        raw = "ALERT tcp connection bytes=999 service=dns flag=REJ"
        out = text_to_compact_csv(raw)
        self.assertIn(",tcp,dns,REJ,999,", out)

    def test_pipeline_with_messy_text(self):
        raw = "duration=1 protocol=udp service=domain_u src_bytes=50 dst_bytes=10 label=normal"
        csv_data = text_to_compact_csv(raw)
        entries = LogProcessor(1).process(csv_data)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].protocol_type, "udp")


if __name__ == "__main__":
    unittest.main()
