"""plane_trust threading (Phase 4, oversight/DESIGN.md; CONTRACT.md §4).

The substrate trust tier is operator-declared, stamped onto ground-truth-derived findings only,
and never part of a finding's identity. These pin that behaviour end to end.
"""
import tempfile
import unittest
from pathlib import Path

from agentwatch.contract import PlaneTrust
from agentwatch.findings import (
    DETECTOR_DIVERGENCE,
    DETECTOR_ORPHAN_SYSCALL,
    DETECTOR_SELF_MOD,
    DETECTOR_UNEVALUABLE,
    Finding,
    stamp_plane_trust,
)
from agentwatch.run import Config, run_once
from tests.test_fork_gap import ForkGapEndToEndTest

AGENT_UID = 1000


def _finding(detector: str, fid: str = "x") -> Finding:
    return Finding(id=fid, detector=detector, ts=1.0, summary=detector)


class StampPlaneTrustTest(unittest.TestCase):
    def test_only_ground_truth_findings_are_stamped(self) -> None:
        findings = [
            _finding(DETECTOR_ORPHAN_SYSCALL, "a"),
            _finding(DETECTOR_UNEVALUABLE, "b"),
            _finding(DETECTOR_DIVERGENCE, "c"),   # transcript plane
            _finding(DETECTOR_SELF_MOD, "d"),     # filesystem baseline
        ]
        out = {f.detector: f.plane_trust for f in stamp_plane_trust(findings, PlaneTrust.UNFORGEABLE.value)}
        # ground-truth-derived: carry the tier
        self.assertEqual(out[DETECTOR_ORPHAN_SYSCALL], "unforgeable")
        self.assertEqual(out[DETECTOR_UNEVALUABLE], "unforgeable")
        # NOT ground-truth-derived: the plane does not vouch for these -> no claim
        self.assertIsNone(out[DETECTOR_DIVERGENCE])
        self.assertIsNone(out[DETECTOR_SELF_MOD])

    def test_none_tier_leaves_everything_unstamped(self) -> None:
        findings = [_finding(DETECTOR_ORPHAN_SYSCALL, "a")]
        self.assertIsNone(stamp_plane_trust(findings, None)[0].plane_trust)

    def test_stamp_does_not_change_finding_id(self) -> None:
        # identity is the event, not the operator's trust declaration -> dedup stays stable
        f = _finding(DETECTOR_ORPHAN_SYSCALL, "stable-id")
        for tier in (None, PlaneTrust.UNFORGEABLE.value, PlaneTrust.HOST_SHARED.value):
            self.assertEqual(stamp_plane_trust([f], tier)[0].id, "stable-id")


class FindingSerializationTest(unittest.TestCase):
    def test_round_trip_preserves_plane_trust(self) -> None:
        f = Finding(id="a", detector=DETECTOR_ORPHAN_SYSCALL, ts=1.0, summary="s", plane_trust="unforgeable")
        self.assertEqual(Finding.from_json(f.to_json()).plane_trust, "unforgeable")

    def test_old_line_without_field_loads_as_none(self) -> None:
        # a findings.jsonl line written before plane_trust existed must still load
        legacy = '{"id": "a", "detector": "orphan_syscall", "ts": 1.0, "summary": "s", "evidence": {}, "session_id": null}'
        self.assertIsNone(Finding.from_json(legacy).plane_trust)


class RunOnceStampingTest(unittest.TestCase):
    def test_unforgeable_tier_reaches_the_written_finding(self) -> None:
        # fork-gap-without-clone -> one UNEVALUABLE (ground-truth) finding; declared UNFORGEABLE.
        log = ForkGapEndToEndTest()._log(include_clone=False)
        with tempfile.TemporaryDirectory() as d:
            dp = Path(d)
            (dp / "audit.log").write_text(log)
            findings = run_once(
                Config(
                    agent_uid=AGENT_UID,
                    audit_log_path=dp / "audit.log",
                    findings_path=dp / "findings.jsonl",
                    state_path=dp / "state.json",
                    plane_trust=PlaneTrust.UNFORGEABLE,
                ),
                now=1000.0,
            )
            u = next(f for f in findings if f.detector == DETECTOR_UNEVALUABLE)
            self.assertEqual(u.plane_trust, "unforgeable")
            # and it persisted to disk with the tier
            self.assertIn('"plane_trust": "unforgeable"', (dp / "findings.jsonl").read_text())

    def test_default_config_leaves_findings_unstamped(self) -> None:
        log = ForkGapEndToEndTest()._log(include_clone=False)
        with tempfile.TemporaryDirectory() as d:
            dp = Path(d)
            (dp / "audit.log").write_text(log)
            findings = run_once(
                Config(
                    agent_uid=AGENT_UID,
                    audit_log_path=dp / "audit.log",
                    findings_path=dp / "findings.jsonl",
                    state_path=dp / "state.json",
                ),
                now=1000.0,
            )
            u = next(f for f in findings if f.detector == DETECTOR_UNEVALUABLE)
            self.assertIsNone(u.plane_trust)


class CliFlagTest(unittest.TestCase):
    def test_plane_trust_flag_maps_to_enum(self) -> None:
        from agentwatch.cli import _build_parser, _config_from_args

        args = _build_parser().parse_args(["--agent-uid", "1000", "--plane-trust", "unforgeable"])
        self.assertEqual(_config_from_args(args).plane_trust, PlaneTrust.UNFORGEABLE)

    def test_plane_trust_omitted_is_none(self) -> None:
        from agentwatch.cli import _build_parser, _config_from_args

        args = _build_parser().parse_args(["--agent-uid", "1000"])
        self.assertIsNone(_config_from_args(args).plane_trust)

    def test_invalid_tier_rejected(self) -> None:
        from agentwatch.cli import _build_parser

        with self.assertRaises(SystemExit):
            _build_parser().parse_args(["--agent-uid", "1000", "--plane-trust", "nonsense"])


if __name__ == "__main__":
    unittest.main()
