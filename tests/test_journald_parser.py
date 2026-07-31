import unittest
from pathlib import Path

from oversight_console.events import LAN_DROP
from oversight_console.groundtruth.journald import iter_lan_drops, parse_lines

SAMPLE = Path(__file__).parent / "fixtures" / "journald" / "sample_journal.jsonl"


class JournaldParserTest(unittest.TestCase):
    def test_parses_valid_lines_skips_bad_ones(self) -> None:
        with SAMPLE.open() as fh:
            events, stats = parse_lines(fh)
        # 5 lines total: 3 valid (sudo, 2x DROP-LAN), 1 invalid JSON, 1 missing timestamp
        self.assertEqual(stats.lines_total, 5)
        self.assertEqual(len(events), 3)
        self.assertEqual(stats.lines_skipped, 2)
        self.assertIn("json_decode_error", stats.skip_reasons)
        self.assertIn("missing_or_bad_timestamp", stats.skip_reasons)

    def test_drop_lan_detection(self) -> None:
        with SAMPLE.open() as fh:
            events, _ = parse_lines(fh)
        drops = list(iter_lan_drops(events))
        self.assertEqual(len(drops), 2)
        self.assertTrue(all(e.kind == LAN_DROP for e in drops))
        self.assertAlmostEqual(drops[0].ts, 1700000005.25)

    def test_timestamp_is_microsecond_epoch_converted_to_seconds(self) -> None:
        with SAMPLE.open() as fh:
            events, _ = parse_lines(fh)
        sudo_event = events[0]
        self.assertAlmostEqual(sudo_event.ts, 1700000000.0)
        self.assertEqual(sudo_event.pid, 500)
        self.assertEqual(sudo_event.comm, "sudo")

    def test_never_raises_on_garbage(self) -> None:
        events, stats = parse_lines(["", "null", "[1,2]", '{"a": 1}'])
        self.assertEqual(events, [])
        self.assertGreater(stats.lines_skipped, 0)


if __name__ == "__main__":
    unittest.main()
