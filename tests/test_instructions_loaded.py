"""The instructions-loaded tripwire (warden D35/D36): parsing, finding identity, trust tier, and
the run_once wiring.

The load-bearing claims, and where each is pinned:

* ANY event is a finding - there is no legitimate event, so there is no threshold to tune
  (`OneEventIsTheFindingTest`).
* Identity is the verbatim line, not the detection time - so re-reading a growing append-only log
  on every poll surfaces each event exactly once (`FindingIdentityTest`, `RunOnceWiringTest`).
* It is NOT ground truth: the hook that writes the log runs at the agent's own privilege
  (`TrustTierTest`).
"""
import json
import tempfile
import unittest
from pathlib import Path

from agentwatch.contract import PlaneTrust
from agentwatch.detectors.instructions_loaded import parse_events, read_events
from agentwatch.findings import (
    DETECTOR_INSTRUCTIONS_LOADED,
    GROUND_TRUTH_DETECTORS,
    instructions_loaded_finding,
    stamp_plane_trust,
)
from agentwatch.run import Config, run_once

AGENT_UID = 4000

# Shaped after the event warden's D35 validation actually captured on gembox from a real Claude
# Code client (a planted /root/CLAUDE.md loading with claudeMdExcludes temporarily cleared), not
# after a payload anyone wished for. Note what it does NOT contain: a timestamp. That absence is
# why this detector does not window - see DECISIONS.md D36 / warden's D36.
REAL_SHAPED_EVENT = {
    "hook_event_name": "InstructionsLoaded",
    "file_path": "/root/CLAUDE.md",
    "memory_type": "Project",
    "load_reason": "session_start",
    "session_id": "0d0c1b6e-1111-4444-9999-abcdefabcdef",
    "transcript_path": "/root/.claude/projects/-root/0d0c1b6e.jsonl",
}


def _line(**overrides) -> str:
    record = dict(REAL_SHAPED_EVENT)
    record.update(overrides)
    return json.dumps(record)


class ParseEventsTest(unittest.TestCase):
    def test_real_shaped_event_parses_its_identifying_fields(self) -> None:
        events = parse_events(_line() + "\n")
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertTrue(ev.parsed)
        self.assertEqual(ev.file_path, "/root/CLAUDE.md")
        self.assertEqual(ev.memory_type, "Project")
        self.assertEqual(ev.load_reason, "session_start")
        self.assertEqual(ev.session_id, REAL_SHAPED_EVENT["session_id"])

    def test_empty_and_blank_only_logs_have_no_events(self) -> None:
        # The hook creates this file only by appending a payload, so empty means "never fired" -
        # the same reading warden's `verify` ring takes.
        self.assertEqual(parse_events(""), [])
        self.assertEqual(parse_events("\n\n   \n"), [])

    def test_multiple_events_are_kept_in_order(self) -> None:
        text = _line(file_path="/root/CLAUDE.md") + "\n" + _line(file_path="/root/.claude/rules/x.md") + "\n"
        events = parse_events(text)
        self.assertEqual([e.file_path for e in events], ["/root/CLAUDE.md", "/root/.claude/rules/x.md"])

    def test_unparseable_line_is_still_an_event(self) -> None:
        # "Something wrote to this log" is the whole claim; a garbled write is no less a write. A
        # detector that dropped what it could not parse would be blind to exactly the novel case.
        events = parse_events("{not json at all\n")
        self.assertEqual(len(events), 1)
        self.assertFalse(events[0].parsed)
        self.assertIsNone(events[0].file_path)
        self.assertEqual(events[0].raw, "{not json at all")

    def test_valid_json_that_is_not_an_object_is_an_unparsed_event(self) -> None:
        events = parse_events('["not", "an", "object"]\n')
        self.assertEqual(len(events), 1)
        self.assertFalse(events[0].parsed)

    def test_read_events_on_a_missing_file_returns_empty_not_raise(self) -> None:
        # The absent case is the NORMAL one (the hook never fired), so it must not be an error.
        self.assertEqual(read_events("/nonexistent/path/.instructions-loaded.jsonl"), [])


class OneEventIsTheFindingTest(unittest.TestCase):
    def test_a_single_event_produces_a_finding_naming_the_file(self) -> None:
        finding = instructions_loaded_finding(parse_events(_line())[0], ts=100.0)
        self.assertEqual(finding.detector, DETECTOR_INSTRUCTIONS_LOADED)
        self.assertIn("/root/CLAUDE.md", finding.summary)
        self.assertIn("claudeMdExcludes", finding.summary)
        self.assertEqual(finding.evidence["load_reason"], "session_start")
        self.assertEqual(finding.session_id, REAL_SHAPED_EVENT["session_id"])

    def test_evidence_carries_the_raw_line_verbatim(self) -> None:
        raw = _line()
        finding = instructions_loaded_finding(parse_events(raw)[0], ts=100.0)
        self.assertEqual(finding.evidence["raw_event"], raw)

    def test_an_unparseable_event_still_produces_a_finding(self) -> None:
        finding = instructions_loaded_finding(parse_events("garbage!")[0], ts=100.0)
        self.assertEqual(finding.detector, DETECTOR_INSTRUCTIONS_LOADED)
        self.assertIn("unparseable", finding.summary)
        self.assertEqual(finding.evidence["raw_event"], "garbage!")
        self.assertFalse(finding.evidence["parsed"])


class FindingIdentityTest(unittest.TestCase):
    def test_same_line_at_a_different_detection_time_is_the_same_finding(self) -> None:
        # Detection time must NOT be part of the identity, or every poll would re-report the whole
        # log. The payload has no timestamp of its own, so the verbatim line is the only identity.
        ev = parse_events(_line())[0]
        self.assertEqual(
            instructions_loaded_finding(ev, ts=1.0).id,
            instructions_loaded_finding(ev, ts=99999.0).id,
        )

    def test_a_different_event_is_a_different_finding(self) -> None:
        a = instructions_loaded_finding(parse_events(_line())[0], ts=1.0)
        b = instructions_loaded_finding(
            parse_events(_line(file_path="/root/CLAUDE.local.md"))[0], ts=1.0
        )
        self.assertNotEqual(a.id, b.id)

    def test_a_new_session_reloading_the_same_file_is_a_new_finding(self) -> None:
        # The session_id in the payload makes the second session's load a distinct occurrence -
        # which is what a per-session tripwire has to report.
        a = instructions_loaded_finding(parse_events(_line())[0], ts=1.0)
        b = instructions_loaded_finding(parse_events(_line(session_id="second-session"))[0], ts=1.0)
        self.assertNotEqual(a.id, b.id)


class TrustTierTest(unittest.TestCase):
    def test_the_detector_is_not_ground_truth(self) -> None:
        # The hook process runs as container-root, the same privilege as the agent it watches, so
        # the log is in-band and truncatable. Claiming a substrate tier for it would be false.
        self.assertNotIn(DETECTOR_INSTRUCTIONS_LOADED, GROUND_TRUTH_DETECTORS)

    def test_a_declared_unforgeable_plane_does_not_stamp_this_finding(self) -> None:
        finding = instructions_loaded_finding(parse_events(_line())[0], ts=1.0)
        stamped = stamp_plane_trust([finding], PlaneTrust.UNFORGEABLE.value)
        self.assertIsNone(stamped[0].plane_trust)


class RunOnceWiringTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.log = self.dir / "instructions-loaded.jsonl"
        self.config = Config(
            agent_uid=AGENT_UID,
            instructions_loaded_path=self.log,
            findings_path=self.dir / "findings.jsonl",
            state_path=self.dir / "state.json",
            self_mod_watched_paths=(),
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _findings(self, now: float):
        return [f for f in run_once(self.config, now=now) if f.detector == DETECTOR_INSTRUCTIONS_LOADED]

    def test_no_log_file_no_findings(self) -> None:
        self.assertEqual(self._findings(now=1000.0), [])

    def test_empty_log_no_findings(self) -> None:
        self.log.write_text("")
        self.assertEqual(self._findings(now=1000.0), [])

    def test_unconfigured_path_leaves_the_detector_silent(self) -> None:
        # A caller that never collected the log (a Gemini home, or one with no hook wired) must get
        # silence, not a crash and not a false pass claim.
        self.log.write_text(_line() + "\n")
        self.config.instructions_loaded_path = None
        self.assertEqual(self._findings(now=1000.0), [])

    def test_every_logged_event_becomes_a_finding(self) -> None:
        self.log.write_text(_line() + "\n" + _line(session_id="s2") + "\n")
        findings = self._findings(now=1000.0)
        self.assertEqual(len(findings), 2)

    def test_repolling_an_unchanged_log_reports_nothing_new(self) -> None:
        self.log.write_text(_line() + "\n")
        self.assertEqual(len(self._findings(now=1000.0)), 1)
        # Same log, later poll: dedup by verbatim line keeps the continuous path quiet. This is
        # what makes windowing unnecessary rather than merely tolerable.
        self.assertEqual(self._findings(now=2000.0), [])

    def test_only_the_appended_event_is_new_on_the_next_poll(self) -> None:
        self.log.write_text(_line() + "\n")
        self._findings(now=1000.0)
        with self.log.open("a") as fh:
            fh.write(_line(session_id="s2", file_path="/root/.claude/rules/injected.md") + "\n")
        new = self._findings(now=2000.0)
        self.assertEqual(len(new), 1)
        self.assertEqual(new[0].evidence["file_path"], "/root/.claude/rules/injected.md")

    def test_the_finding_lands_in_findings_jsonl(self) -> None:
        self.log.write_text(_line() + "\n")
        self._findings(now=1000.0)
        written = (self.dir / "findings.jsonl").read_text()
        self.assertIn('"detector": "instructions_loaded"', written)
        self.assertIn("/root/CLAUDE.md", written)


if __name__ == "__main__":
    unittest.main()
