"""
tests/unit/test_log_processor.py
Unit tests for LogProcessor — Section 3.4.5, Table 3.5.
Uses Python built-in unittest (no external test framework).
"""
import unittest, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from backend.preprocessing.log_processor import LogProcessor, NSL_KDD_COLUMNS

def row(**kw):
    d = {"duration":"0","protocol_type":"tcp","service":"http","flag":"SF",
         "src_bytes":"500","dst_bytes":"1000","land":"0","wrong_fragment":"0",
         "urgent":"0","hot":"0","num_failed_logins":"0","logged_in":"1",
         "num_compromised":"0","root_shell":"0","su_attempted":"0","num_root":"0",
         "num_file_creations":"0","num_shells":"0","num_access_files":"0",
         "num_outbound_cmds":"0","is_host_login":"0","is_guest_login":"0",
         "count":"1","srv_count":"1","serror_rate":"0.0","srv_serror_rate":"0.0",
         "rerror_rate":"0.0","srv_rerror_rate":"0.0","same_srv_rate":"1.0",
         "diff_srv_rate":"0.0","srv_diff_host_rate":"0.0","dst_host_count":"1",
         "dst_host_srv_count":"1","dst_host_same_srv_rate":"1.0",
         "dst_host_diff_srv_rate":"0.0","dst_host_same_src_port_rate":"1.0",
         "dst_host_srv_diff_host_rate":"0.0","dst_host_serror_rate":"0.0",
         "dst_host_srv_serror_rate":"0.0","dst_host_rerror_rate":"0.0",
         "dst_host_srv_rerror_rate":"0.0","label":"normal","difficulty_level":"0"}
    d.update(kw)
    return ",".join(d[c] for c in NSL_KDD_COLUMNS)

csv = lambda *rows: "\n".join(rows)

class TestParsing(unittest.TestCase):
    def test_single_row(self):
        self.assertEqual(len(LogProcessor(1).process(csv(row()))), 1)
    def test_multiple_rows(self):
        self.assertEqual(len(LogProcessor(1).process(csv(row(),row(label="smurf"),row(label="neptune")))), 3)
    def test_empty_input(self):
        self.assertEqual(LogProcessor(1).process(""), [])
    def test_skip_blank_lines(self):
        self.assertEqual(len(LogProcessor(1).process(row() + "\n\n" + row())), 2)
    def test_skip_header(self):
        self.assertEqual(len(LogProcessor(1).process(csv(",".join(NSL_KDD_COLUMNS), row()))), 1)

class TestTransformation(unittest.TestCase):
    def _entry(self, **kw):
        return LogProcessor(1).process(csv(row(**kw)))[0]
    def test_required_attributes(self):
        e = self._entry()
        for attr in ("timestamp","source_ip","destination_ip","event_type","message"):
            self.assertIsNotNone(getattr(e, attr))
    def test_normal_label(self):
        self.assertEqual(self._entry(label="normal").event_type, "NORMAL")
    def test_attack_label(self):
        self.assertEqual(self._entry(label="neptune").event_type, "neptune")
    def test_numeric_cast(self):
        e = self._entry(src_bytes="12345", dst_bytes="67890", duration="3.5")
        self.assertEqual(e.src_bytes, 12345)
        self.assertEqual(e.dst_bytes, 67890)
        self.assertAlmostEqual(e.duration, 3.5)
    def test_file_id(self):
        self.assertEqual(LogProcessor(42).process(csv(row()))[0].file_id, 42)
    def test_wrong_fragment(self):
        self.assertEqual(self._entry(wrong_fragment="3").wrong_fragment, 3)
    def test_land(self):
        self.assertEqual(self._entry(land="1").land, 1)

class TestFiltering(unittest.TestCase):
    def test_bad_bytes_rejected(self):
        p = LogProcessor(1)
        entries = p.process(csv(row(src_bytes="BAD")))
        self.assertEqual(len(entries), 0)
        self.assertGreater(len(p.errors), 0)
    def test_good_bad_mix(self):
        p = LogProcessor(1)
        entries = p.process(csv(row(), row(src_bytes="BAD")))
        self.assertEqual(len(entries), 1)

if __name__ == "__main__":
    unittest.main()
