"""Conformance to the oversight-component contract (oversight/CONTRACT.md, agentwatch/contract.py).

These pin the surface the deployment stack depends on: the Verdict vocabulary, the substrate-trust
tiers, and that the real v1 adapters/parsers satisfy the contract's Protocols. An alternative
oversight provider passes these same checks to be a drop-in.
"""
import unittest

from agentwatch import contract
from agentwatch.contract import (
    Finding,
    GroundTruthEvent,
    GroundTruthParser,
    NormalizedEvent,
    PlaneTrust,
    TranscriptSource,
    Verdict,
)


class ContractVocabularyTest(unittest.TestCase):
    def test_verdict_vocabulary_is_exactly_the_four(self) -> None:
        # CONFIRMED/GAP/NONE are canon's; UNEVALUABLE is the local honesty extension (G24).
        self.assertEqual(
            {v.name for v in Verdict}, {"CONFIRMED", "GAP", "NONE", "UNEVALUABLE"}
        )

    def test_plane_trust_tiers(self) -> None:
        self.assertEqual(
            {t.name for t in PlaneTrust},
            {"UNFORGEABLE", "HOST_SHARED", "SELF_REPORTED"},
        )

    def test_canonical_types_are_reexported(self) -> None:
        for name in ("Verdict", "Finding", "NormalizedEvent", "GroundTruthEvent"):
            self.assertIn(name, contract.__all__)
        self.assertTrue(issubclass(Finding, object))
        self.assertTrue(issubclass(NormalizedEvent, object))
        self.assertTrue(issubclass(GroundTruthEvent, object))


class AdapterConformanceTest(unittest.TestCase):
    def test_claude_transcript_adapter_satisfies_transcript_source(self) -> None:
        from agentwatch import runtimes

        adapter = runtimes.CLAUDE.adapter_factory()
        self.assertIsInstance(adapter, TranscriptSource)

    def test_ground_truth_parsers_satisfy_ground_truth_parser(self) -> None:
        from agentwatch.groundtruth import audit_log, journald

        for parser in (audit_log.parse_lines, journald.parse_lines):
            self.assertIsInstance(parser, GroundTruthParser)
            events, _stats = parser([])  # empty input -> ([], stats); never raises
            self.assertEqual(events, [])


if __name__ == "__main__":
    unittest.main()
