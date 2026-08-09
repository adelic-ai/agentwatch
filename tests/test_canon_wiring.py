"""Acceptance for the canon wiring (CANON-WIRING-SPEC.md §6). SYNTHETIC fixtures only — hand-built
NormalizedEvent / GroundTruthEvent, NO real prompts.

Proves, against the REAL canon API (skipped cleanly if canon is not importable):
  1. orphan exec  → CONFIRMED → a detection_verdict that (a) validates against
     detection_verdict.schema.json AND (b) passes canon's SHACL `well_formed` shapes.
  2. runtime-internal exec → NONE → an honest verdict, guarantee tier NOT inflated.
  3. fork gap → a fidelity_attestation with cause.kind=missing-telemetry, schema-valid.
  4. every emitted verdict's provenance cid resolves to a well-formed PROV-O DAG (to_prov + SHACL).
  6. honesty: emitted tiers stay ≤ well_formed and `calibration` is absent (the anti-theater gate).
(§6.5 canon regression is canon's own suite — run separately, see DECISIONS.md.)
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from agentwatch import canon_emit
from agentwatch.events import EXEC, GroundTruthEvent, NormalizedEvent, REASONING, TOOL_USE
from agentwatch.reconciler.divergence import reconcile_divergence
from agentwatch.reconciler.orphan import reconcile_orphans_scoped
from agentwatch.reconciler.verdict import Verdict

if not canon_emit.CANON_AVAILABLE:  # pragma: no cover
    raise unittest.SkipTest("canon not importable — canon wiring acceptance skipped")

import detection  # noqa: E402
import jsonschema  # noqa: E402
from provenance import (  # noqa: E402
    CustodyAttestation,
    evidence_digest,
    to_prov,
    validate_graph,
    well_formed_shapes,
)

_CANON = Path(detection.__file__).resolve().parents[4]
_CONTRACTS = _CANON / "contracts"
_SHAPES = _CONTRACTS / "shapes"
_HONEST_TIERS = {"absent", "well_formed"}

AGENT_UID = 1000
RUNTIME_EXE = "/usr/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe"
WINDOW = 15.0


def _schema(name: str) -> dict:
    return json.loads((_CONTRACTS / name).read_text())


def _well_formed_shapes_graph():
    """Generic PROV-O well-formedness + canon's DETECTION-DOMAIN shapes — the same merge
    emit_detection_verdict uses to EARN the tier (contracts/shapes/*.ttl)."""
    g = well_formed_shapes()
    for shape in ("detection.shapes.ttl", "cross_model.shapes.ttl"):
        p = _SHAPES / shape
        if p.exists():
            g.parse(p, format="turtle")
    return g


def gt(pid, ppid, exe, ts, comm=None, args=(), uid=AGENT_UID):
    return GroundTruthEvent(
        ts=ts, kind=EXEC, pid=pid, ppid=ppid, uid=uid, exe=exe, comm=comm or exe, args=args,
        source="audit",
    )


class OrphanConfirmedTest(unittest.TestCase):
    def setUp(self):
        # a planted orphan: `nc` spawned directly by the runtime, no authorizing tool_use.
        self.gt_events = [
            gt(pid=1, ppid=0, exe=RUNTIME_EXE, comm="claude", ts=1000.0),
            gt(pid=2, ppid=1, exe="/usr/bin/nc", comm="nc", ts=1005.0),
        ]
        cands = reconcile_orphans_scoped(self.gt_events, [], agent_uid=AGENT_UID, window_seconds=WINDOW)
        self.cand = next(c for c in cands if c.event.pid == 2)
        self.assertEqual(self.cand.verdict, Verdict.CONFIRMED)

    def test_confirmed_verdict_validates_against_schema(self):
        v = canon_emit.orphan_verdict(self.cand, host="capsule-1", agent_uid=AGENT_UID)
        c = v.to_contract()
        jsonschema.validate(c, _schema("detection_verdict.schema.json"))
        self.assertEqual(c["decision"], "true")           # CONFIRMED → true
        self.assertEqual(c["technique"], canon_emit.TECHNIQUE_ORPHAN)
        self.assertEqual(c["w_record"]["who"], "true")     # agent uid known
        self.assertEqual(c["w_record"]["what"], "true")    # exec artifact established
        self.assertEqual(c["w_record"]["where"], "true")   # host supplied
        self.assertEqual(c["w_record"]["when"], "none")    # no temporal ∀-validate — honest

    def test_confirmed_verdict_passes_shacl_well_formed_shapes(self):
        v = canon_emit.orphan_verdict(self.cand, host="capsule-1", agent_uid=AGENT_UID)
        root = canon_emit.orphan_provenance_root(self.cand, host="capsule-1", agent_uid=AGENT_UID)
        # the root the verdict is about (content-addressed — same id)
        self.assertEqual(root.id, v.to_contract()["provenance"])
        report = validate_graph(to_prov(root), _well_formed_shapes_graph())
        self.assertTrue(report.conforms, report.text)

    def test_custody_none_unsigned_but_true_when_attested(self):
        # default: unsigned auditd feed → custody honestly NONE
        c = canon_emit.orphan_verdict(self.cand, host="h", agent_uid=AGENT_UID).to_contract()
        self.assertEqual(c["custody"], "none")
        # signed collector: record bytes + a matching attestation → custody earns TRUE
        rec = b"type=SYSCALL ... exe=/usr/bin/nc pid=2"
        att = CustodyAttestation(product_digest=evidence_digest(rec))
        c2 = canon_emit.orphan_verdict(
            self.cand, host="h", agent_uid=AGENT_UID,
            audit_record_bytes=rec, custody_attestation=att,
        ).to_contract()
        self.assertEqual(c2["custody"], "true")


class RuntimeInternalNoneTest(unittest.TestCase):
    def setUp(self):
        # `rg` (ripgrep) exec'd directly by the runtime — runtime-internal, no tool_use can authorize.
        self.gt_events = [
            gt(pid=1, ppid=0, exe=RUNTIME_EXE, comm="claude", ts=1000.0),
            gt(pid=2, ppid=1, exe="/usr/bin/rg", comm="rg", ts=1002.0),
        ]
        cands = reconcile_orphans_scoped(self.gt_events, [], agent_uid=AGENT_UID, window_seconds=WINDOW)
        self.cand = next(c for c in cands if c.event.pid == 2)
        self.assertEqual(self.cand.verdict, Verdict.NONE)

    def test_none_verdict_is_honest_and_uninflated(self):
        v = canon_emit.orphan_verdict(self.cand, host="capsule-1", agent_uid=AGENT_UID)
        c = v.to_contract()
        jsonschema.validate(c, _schema("detection_verdict.schema.json"))
        self.assertEqual(c["decision"], "none")            # NONE → no claim
        self.assertEqual(c["w_record"]["what"], "none")    # no artifact claim
        self.assertEqual(c["score"], 0.0)                  # no graded belief
        self.assertIn(c["guarantee"]["tier"], _HONEST_TIERS)   # tier NOT inflated
        self.assertNotIn("calibration", c)                 # uncalibrated — honest absence


class DivergenceTest(unittest.TestCase):
    def test_divergent_verdict_validates(self):
        events = [
            NormalizedEvent(ts=1.0, kind=REASONING, text="I'll Read the config file",
                            uuid="r1", session_id="s1"),
            NormalizedEvent(ts=2.0, kind=TOOL_USE, tool_name="Bash", uuid="a1", session_id="s1",
                            tool_input={"command": "rm -rf /tmp/x"}),
        ]
        cand = next(c for c in reconcile_divergence(events) if c.is_divergent)
        c = canon_emit.divergence_verdict(cand).to_contract()
        jsonschema.validate(c, _schema("detection_verdict.schema.json"))
        self.assertEqual(c["technique"], canon_emit.TECHNIQUE_DIVERGENCE)
        self.assertEqual(c["decision"], "true")
        self.assertEqual(c["custody"], "none")             # transcript-only, nothing to attest
        self.assertEqual(c["w_record"]["where"], "none")   # transcript carries no host


class ForkGapFidelityTest(unittest.TestCase):
    def test_fork_gap_attestation_missing_telemetry(self):
        att = canon_emit.fork_gap_attestation()
        jsonschema.validate(att, _schema("fidelity_attestation.schema.json"))
        self.assertEqual(att["cause"]["kind"], "missing-telemetry")
        self.assertEqual(att["technique"], canon_emit.TECHNIQUE_ORPHAN)
        self.assertEqual(att["coverage"], "false")
        self.assertEqual(att["evaluation"]["custody"], "none")  # unsigned corpus — honest


class ProvenanceWellFormedTest(unittest.TestCase):
    def test_every_emitted_verdict_provenance_is_well_formed_prov_o(self):
        # one CONFIRMED + one NONE, both roots must resolve to well-formed PROV-O (§6.4).
        events = [
            gt(pid=1, ppid=0, exe=RUNTIME_EXE, comm="claude", ts=1000.0),
            gt(pid=2, ppid=1, exe="/usr/bin/nc", comm="nc", ts=1005.0),
            gt(pid=3, ppid=1, exe="/usr/bin/rg", comm="rg", ts=1002.0),
        ]
        cands = reconcile_orphans_scoped(events, [], agent_uid=AGENT_UID, window_seconds=WINDOW)
        shapes = _well_formed_shapes_graph()
        checked = 0
        for cand in cands:
            if cand.verdict is None:
                continue
            v = canon_emit.orphan_verdict(cand, host="h", agent_uid=AGENT_UID)
            root = canon_emit.orphan_provenance_root(cand, host="h", agent_uid=AGENT_UID)
            self.assertEqual(root.id, v.to_contract()["provenance"])
            self.assertTrue(validate_graph(to_prov(root), shapes).conforms)
            checked += 1
        self.assertGreaterEqual(checked, 2)


class HonestyGateTest(unittest.TestCase):
    """§6.6 — the anti-theater assertion over EVERY verdict this wiring can emit."""

    def _all_verdicts(self):
        gts = [
            gt(pid=1, ppid=0, exe=RUNTIME_EXE, comm="claude", ts=1000.0),
            gt(pid=2, ppid=1, exe="/usr/bin/nc", comm="nc", ts=1005.0),
            gt(pid=3, ppid=1, exe="/usr/bin/rg", comm="rg", ts=1002.0),
        ]
        for cand in reconcile_orphans_scoped(gts, [], agent_uid=AGENT_UID, window_seconds=WINDOW):
            if cand.verdict is not None:
                yield canon_emit.orphan_verdict(cand, host="h", agent_uid=AGENT_UID).to_contract()
        div = [
            NormalizedEvent(ts=1.0, kind=REASONING, text="I'll Read it", uuid="r1", session_id="s1"),
            NormalizedEvent(ts=2.0, kind=TOOL_USE, tool_name="Bash", uuid="a1", session_id="s1"),
        ]
        for cand in reconcile_divergence(div):
            if cand.is_divergent:
                yield canon_emit.divergence_verdict(cand).to_contract()

    def test_tiers_bounded_and_calibration_absent(self):
        seen = 0
        for c in self._all_verdicts():
            self.assertIn(c["guarantee"]["tier"], _HONEST_TIERS,
                          f"tier inflated: {c['guarantee']['tier']}")
            self.assertNotIn("calibration", c, "calibration must stay absent (uncalibrated)")
            seen += 1
        self.assertGreater(seen, 0)


if __name__ == "__main__":
    unittest.main()
