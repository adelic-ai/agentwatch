import tempfile
import unittest
from pathlib import Path

from oversight_console.detectors.agent_flag import parse_entries, read_entries
from oversight_console.detectors.lan_reach import detect_lan_reach
from oversight_console.detectors.self_mod import (
    check_self_modification,
    update_baseline,
)
from oversight_console.detectors.trifecta import detect_lethal_trifecta
from oversight_console.events import EXEC, LAN_DROP, GroundTruthEvent
from oversight_console.findings import (
    agent_flag_finding,
    lan_reach_finding,
    self_mod_finding,
)


class LanReachDetectorTest(unittest.TestCase):
    def test_filters_to_lan_drop_only(self) -> None:
        events = [
            GroundTruthEvent(ts=1.0, kind=EXEC, pid=1, source="audit"),
            GroundTruthEvent(ts=2.0, kind=LAN_DROP, pid=2, comm="curl", source="journald",
                              raw={"MESSAGE": "kernel: DROP-LAN blah"}),
        ]
        drops = detect_lan_reach(events)
        self.assertEqual(len(drops), 1)
        finding = lan_reach_finding(drops[0])
        self.assertEqual(finding.detector, "lan_reach")
        self.assertIn("pid=2", finding.summary)

    def test_no_drops_no_findings(self) -> None:
        events = [GroundTruthEvent(ts=1.0, kind=EXEC, pid=1, source="audit")]
        self.assertEqual(detect_lan_reach(events), [])


class SelfModDetectorTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.settings = self.dir / "settings.json"
        self.settings.write_text('{"hooks": {}}')

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_first_observation_is_not_a_change(self) -> None:
        candidates = check_self_modification(baseline={}, watched_paths=[str(self.settings)])
        self.assertFalse(candidates[0].is_change)
        self.assertTrue(candidates[0].exists)

    def test_unchanged_content_is_not_flagged(self) -> None:
        baseline = update_baseline(check_self_modification({}, [str(self.settings)]))
        candidates = check_self_modification(baseline, [str(self.settings)])
        self.assertFalse(candidates[0].is_change)

    def test_changed_content_is_flagged(self) -> None:
        baseline = update_baseline(check_self_modification({}, [str(self.settings)]))
        self.settings.write_text('{"hooks": {"PreToolUse": "malicious"}}')
        candidates = check_self_modification(baseline, [str(self.settings)])
        self.assertTrue(candidates[0].is_change)
        finding = self_mod_finding(candidates[0], ts=100.0)
        self.assertEqual(finding.detector, "self_mod")
        self.assertIn(str(self.settings), finding.evidence["path"])

    def test_file_created_where_none_existed_before_is_flagged(self) -> None:
        missing = self.dir / "new_config.json"
        baseline = update_baseline(check_self_modification({}, [str(missing)]))
        self.assertIsNone(baseline[str(missing)])
        missing.write_text("{}")
        candidates = check_self_modification(baseline, [str(missing)])
        self.assertTrue(candidates[0].is_change)

    def test_missing_file_stays_missing_not_flagged(self) -> None:
        missing = self.dir / "never_existed.json"
        baseline = update_baseline(check_self_modification({}, [str(missing)]))
        candidates = check_self_modification(baseline, [str(missing)])
        self.assertFalse(candidates[0].is_change)
        self.assertFalse(candidates[0].exists)


class AgentFlagDetectorTest(unittest.TestCase):
    def test_parses_markdown_h2_sections(self) -> None:
        text = (
            "# Needs human\n\n"
            "Empty means quiet.\n\n"
            "## 2026-07-31: sudo prompt appeared unexpectedly\n\n"
            "What: a sudo password prompt blocked a non-interactive script.\n"
            "Why it needs a human: could indicate privilege escalation was attempted.\n\n"
            "## 2026-08-01: ambiguous rollback target\n\n"
            "Two possible commits to roll back to; picked the older one, noting here.\n"
        )
        entries = parse_entries(text)
        self.assertEqual(len(entries), 2)
        self.assertIn("sudo prompt", entries[0].heading)
        self.assertIn("privilege escalation", entries[0].body)
        self.assertIn("ambiguous rollback", entries[1].heading)

    def test_empty_file_no_entries(self) -> None:
        text = "# Needs human\n\nEmpty means quiet - nothing here warrants attention yet.\n"
        self.assertEqual(parse_entries(text), [])

    def test_read_entries_missing_file_returns_empty_not_raise(self) -> None:
        self.assertEqual(read_entries("/nonexistent/path/NEEDS-HUMAN.md"), [])

    def test_same_entry_reparsed_produces_same_finding_id(self) -> None:
        text = "## Something happened\n\nDetails here.\n"
        e1 = parse_entries(text)[0]
        e2 = parse_entries(text)[0]
        f1 = agent_flag_finding(e1, ts=1.0)
        f2 = agent_flag_finding(e2, ts=2.0)  # different detection time, same content
        self.assertEqual(f1.id, f2.id)  # dedup key is content, not detection time


class TrifectaStubTest(unittest.TestCase):
    def test_stub_always_empty(self) -> None:
        self.assertEqual(detect_lethal_trifecta([]), [])
        self.assertEqual(detect_lethal_trifecta([object()]), [])  # never inspects input in v1


if __name__ == "__main__":
    unittest.main()
