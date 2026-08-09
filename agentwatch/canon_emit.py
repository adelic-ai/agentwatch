"""Emit agentwatch reconciliation results into canon's verdict/provenance/fidelity substrate.

This is the **consumer-side** wiring described in CANON-WIRING-SPEC.md: agentwatch (the detector)
imports canon and projects each reconciliation result into canon's *existing* contracts —
``detection_verdict.schema.json`` (via :func:`detection.emit_detection_verdict`), a PROV-O
provenance DAG, and (for agentwatch's structural limits) ``fidelity_attestation.schema.json`` (via
:func:`detection.fidelity.attest_fidelity`). Nothing in canon is reshaped here; the dependency
flows one way (agentwatch → canon), and every field is gated by an honesty rule (spec §3/§5):

* guarantee tier is EARNED by canon's SHACL walk (``well_formed`` at best — never ``bounded`` /
  ``machine_checked``, which would need calibration agentwatch does not have);
* ``calibration`` is left ABSENT (agentwatch is uncalibrated — one run, no conformal/CFAR/FDR bound);
* ``custody`` is ``true`` ONLY where an integrity-providing collector supplies signed record bytes;
  otherwise it is honestly ``none`` (the auditd feed is unsigned).

**canon is an optional dependency.** On a deployment where canon is not importable (the recall
build VM was one — see DECISIONS.md), :data:`CANON_AVAILABLE` is ``False`` and the emit functions
raise a clear error; ``run.py`` checks the flag and simply does not write ``verdicts.jsonl`` rather
than breaking the existing finding pipeline.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Optional

from agentwatch.reconciler.verdict import Verdict

try:  # canon is an OPTIONAL dependency — the finding pipeline must not depend on it
    from detection import build_detection_root, emit_detection_verdict
    from detection.entailment_verdict import (
        CONFIRMED as ENT_CONFIRMED,
        GAP as ENT_GAP,
        NONE as ENT_NONE,
        entailment_to_belnap,
    )
    from detection.fidelity import attest_fidelity
    from forge_core import DetectionVerdict
    from provenance import NONE as B_NONE, TRUE as B_TRUE, CustodyAttestation, evidence_digest

    CANON_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only where canon is absent
    CANON_AVAILABLE = False
    DetectionVerdict = object  # type: ignore

# agent-oversight technique labels (spec §3): honest, non-stretched — NOT a forced ATT&CK id. When
# omega's agentwatch-coverage map lands these gain an ATLAS/ATT&CK mapping; until then they name what
# the detector actually observed.
TECHNIQUE_ORPHAN = "AGENT.orphan-exec"
TECHNIQUE_DIVERGENCE = "AGENT.divergence"

# agentwatch is UNCALIBRATED (one run, no conformal/CFAR/FDR bound). The score the confidence fold
# derives from this nominal operating point is therefore NOT a calibrated probability; the honesty is
# carried structurally by `calibration` being ABSENT and the guarantee tier staying `well_formed`
# (never `bounded`). Documented nominal, deliberately not near 1.0 to avoid dressing it as certainty.
UNCALIBRATED_PVALUE = 0.5

# The local reconciler vocabulary ↔ canon's entailment carrier. The recall branch coded CONFIRMED/
# GAP/NONE as a local enum because canon was not importable then (spec §2 asked to "reuse canon's
# detection.entailment_verdict if importable"); now that it is, this is the seam that routes the local
# classification THROUGH canon's carrier + `entailment_to_belnap`, rather than re-deriving the Belnap
# projection. The values are identical strings, guarded below so drift is caught.
if CANON_AVAILABLE:
    _VERDICT_TO_CARRIER = {
        Verdict.CONFIRMED: ENT_CONFIRMED,
        Verdict.GAP: ENT_GAP,
        Verdict.NONE: ENT_NONE,
    }
    # Drift guard: the local enum values MUST equal canon's carrier constants, or the reuse is a lie.
    assert all(v.value == carrier for v, carrier in _VERDICT_TO_CARRIER.items()), (
        "agentwatch Verdict enum drifted from canon's entailment_verdict carrier constants"
    )


def _require_canon() -> None:
    if not CANON_AVAILABLE:
        raise RuntimeError(
            "canon is not importable in this environment; canon verdict emission is unavailable. "
            "Install canon (detection/forge_core/provenance, [rdf] extra) to enable it."
        )


# --- provenance recipes (the two-plane reconcile, as the verdict root's params) ------------------
# emit_detection_verdict owns root construction (build_detection_root over the ground-truth source);
# the two planes are recorded in the recipe `params` (re-derivable) and the `ref` identity. The
# ground-truth (auditd) plane is the verdict's evidence source — exactly the unforgeable plane canon's
# custody wants to attest (spec §3); the self-report (transcript) plane carries no integrity and rides
# in params. Values are kept str/int/tuple so the Activity id (a repr of sorted params) is stable.


def _orphan_ref_params(candidate, host, agent_uid, session_id, window_seconds):
    ev = candidate.event
    carrier = _VERDICT_TO_CARRIER[candidate.verdict]
    ref = f"agentwatch|orphan-exec|host={host or '?'}|pid={ev.pid}|exe={ev.exe}|ts={ev.ts}"
    params = {
        "detector": "orphan_syscall",
        "ground_truth_plane": f"auditd:exec:pid={ev.pid}:ppid={ev.ppid}:uid={ev.uid}",
        "self_report_plane": f"transcript:session={session_id or '?'}",
        "reconcile": "time-window ancestry: no authorizing tool_use covers the exec's ancestry",
        "window_seconds": window_seconds,
        "verdict": carrier,
        "reason": candidate.reason or "",
        "ancestry": tuple(candidate.ancestry_checked),
        "agent_uid": agent_uid if agent_uid is not None else -1,
        "host": host or "",
        "exe": ev.exe or "",
        "comm": ev.comm or "",
    }
    return ref, params


def orphan_provenance_root(
    candidate,
    *,
    host: Optional[str] = None,
    agent_uid: Optional[int] = None,
    session_id: Optional[str] = None,
    window_seconds: float = 15.0,
    audit_record_bytes: Optional[bytes] = None,
):
    """The canon provenance ``Entity`` (root) for this orphan candidate — the SAME root
    :func:`orphan_verdict` emits (content-addressed on the same ref/params/evidence, so its ``id``
    equals the emitted verdict's ``provenance`` cid). Exposed so a caller can walk / SHACL-validate
    the PROV-O DAG (``to_prov(root)``) independently — the acceptance §6.4 check."""
    _require_canon()
    ref, params = _orphan_ref_params(candidate, host, agent_uid, session_id, window_seconds)
    return build_detection_root(ref, params, evidence=audit_record_bytes)


def orphan_verdict(
    candidate,
    *,
    host: Optional[str] = None,
    agent_uid: Optional[int] = None,
    session_id: Optional[str] = None,
    window_seconds: float = 15.0,
    audit_record_bytes: Optional[bytes] = None,
    custody_attestation: "Optional[CustodyAttestation]" = None,
    pvalue: float = UNCALIBRATED_PVALUE,
) -> "DetectionVerdict":
    """Project one orphan :class:`~agentwatch.reconciler.orphan.OrphanCandidate` into a canon
    ``DetectionVerdict``. Requires ``candidate.verdict`` to be set (CONFIRMED or NONE — the scoped
    reconciler sets it; the unscoped one does not).

    Honesty gates (spec §3):

    * ``decision`` follows canon's carrier: CONFIRMED → ``true`` (a fired detect), NONE → ``none``
      (the plane structurally established no claim — a NO_EVIDENCE leaf, via ``fired=False``).
    * W-record: ``who`` TRUE iff the agent uid is known; ``what``/``how`` TRUE only on a CONFIRMED
      (the exec artifact + ancestry chain established by ground truth); ``when`` always NONE
      (agentwatch runs no temporal ∀-validate); ``where`` TRUE iff a host is known.
    * ``custody`` is TRUE only when signed record bytes + a matching attestation are supplied;
      otherwise NONE (unsigned auditd feed) — never faked.
    * ``calibration`` absent; guarantee tier EARNED by canon's SHACL walk (``well_formed`` at best).
    """
    _require_canon()
    if candidate.verdict is None:
        raise ValueError(
            "orphan_verdict needs a classified candidate (verdict set by reconcile_orphans_scoped)"
        )
    carrier = _VERDICT_TO_CARRIER[candidate.verdict]
    belnap = entailment_to_belnap(carrier)
    fired = belnap == B_TRUE  # CONFIRMED/GAP → fired; NONE → no claim

    ref, params = _orphan_ref_params(candidate, host, agent_uid, session_id, window_seconds)

    who = B_TRUE if agent_uid is not None else B_NONE
    where = B_TRUE if host else B_NONE
    what = B_TRUE if fired else B_NONE  # the exec artifact — established only on a real detect
    how = B_TRUE if fired else B_NONE   # the ancestry-chain mechanism — asserted only on a detect

    # Earned custody only where the collector provides integrity (spec §3/§5). Default: no evidence
    # bytes ⇒ by-reference source ⇒ custody NONE (honest, unsigned auditd).
    return emit_detection_verdict(
        ref,
        technique=TECHNIQUE_ORPHAN,
        pvalue=pvalue,
        params=params,
        fired=fired,
        who=who,
        what=what,
        when=B_NONE,
        where=where,
        how=how,
        evidence=audit_record_bytes,
        attestation=custody_attestation,
    )


def divergence_verdict(
    candidate,
    *,
    host: Optional[str] = None,
    session_id: Optional[str] = None,
    pvalue: float = UNCALIBRATED_PVALUE,
) -> "DetectionVerdict":
    """Project one divergent :class:`~agentwatch.reconciler.divergence.DivergenceCandidate` into a
    canon ``DetectionVerdict``. Only meaningful for ``is_divergent`` candidates.

    Divergence is a within-session, transcript-plane-ONLY check (stated tools vs actual tool_use) —
    there is no unforgeable ground-truth plane, so ``custody`` is always NONE (nothing to attest) and
    ``where`` is NONE (the transcript carries no host). ``who`` TRUE iff the session is identified;
    ``what``/``how`` TRUE (the actual tool_use and the stated-vs-actual mechanism are established from
    the transcript). ``when`` NONE (no temporal ∀-validate)."""
    _require_canon()
    if not getattr(candidate, "is_divergent", False):
        raise ValueError("divergence_verdict is only for is_divergent candidates")
    r_ev = candidate.reasoning_event
    a_ev = candidate.actual_tool_use
    sid = session_id or a_ev.session_id
    ref = f"agentwatch|divergence|session={sid or '?'}|r={r_ev.uuid}|a={a_ev.uuid}"
    params = {
        "detector": "divergence",
        "self_report_plane": f"transcript:session={sid or '?'}",
        "reconcile": "reasoning named tool(s) the next tool_use did not use (lexical, within-session)",
        "verdict": ENT_CONFIRMED,
        "stated_tools": tuple(candidate.stated_tools),
        "actual_tool": a_ev.tool_name or "",
    }
    return emit_detection_verdict(
        ref,
        technique=TECHNIQUE_DIVERGENCE,
        pvalue=pvalue,
        params=params,
        fired=True,
        who=B_TRUE if sid else B_NONE,
        what=B_TRUE,   # the actual tool_use is recorded in the transcript
        when=B_NONE,
        where=B_NONE,  # transcript plane carries no host
        how=B_TRUE,    # the stated-vs-actual mechanism is established (lexically)
    )


# --- fidelity attestations — agentwatch's structural limits, machine-checkable (spec §4) ---------

# agentwatch's execve-only observation, modeled as a Sigma-shaped rule so canon's attest_fidelity can
# evaluate it and DERIVE the coverage verdict + cause. fork-without-exec instances lack the execve
# fields the rule keys on ⇒ attest_fidelity yields coverage=false, cause.kind=missing-telemetry
# (the honest "wrong observation channel, not a rule logic gap"). This REUSES canon's fidelity
# machinery rather than hand-asserting the attestation.
_ORPHAN_EXEC_RULE = {
    "id": TECHNIQUE_ORPHAN,
    "detection": {"selection": {"syscall": "execve"}, "condition": "selection"},
}

# A default synthetic fork-gap corpus: forked pids that never execve'd, so the audit record carries no
# execve field for the rule to key on (the fork/clone gap of an execve-only auditd config).
_DEFAULT_FORK_POSITIVES = [
    {"event": "fork", "syscall_group": "process", "pid": 4242, "ppid": 4200},
    {"event": "clone", "syscall_group": "process", "pid": 4243, "ppid": 4200},
]


def fork_gap_attestation(
    *,
    corpus_id: str = "synthetic:fork-without-exec",
    corpus_cid: str = "cid:synthetic:fork-gap:v1",
    positives: Optional[list] = None,
) -> dict:
    """A ``fidelity_attestation`` for agentwatch's fork/clone gap: fork-without-exec is invisible to
    an execve-only auditd config, so the orphan detector structurally cannot observe it. Reuses
    :func:`detection.fidelity.attest_fidelity`, which evaluates the execve-keyed rule on the
    fork-gap instances and derives ``coverage=false`` + ``cause.kind=missing-telemetry`` (spec §4).
    Conforms to ``fidelity_attestation.schema.json``."""
    _require_canon()
    positives = positives if positives is not None else _DEFAULT_FORK_POSITIVES
    rule_bytes = json.dumps(_ORPHAN_EXEC_RULE, sort_keys=True).encode("utf-8")
    return attest_fidelity(
        _ORPHAN_EXEC_RULE,
        positives,
        TECHNIQUE_ORPHAN,
        rule_bytes=rule_bytes,
        corpus_id=corpus_id,
        corpus_cid=corpus_cid,
        event_count=len(positives),
        not_claimed=[
            "does NOT claim the orphan detector misses exec-based orphans — it catches those; this "
            "attests only the fork/clone-without-exec blind spot of an execve-only auditd config",
            "scoped to this observation channel (execve syscalls) — a fork/exit-instrumented config "
            "would change coverage",
        ],
        rules_not_evaluated=[
            "the divergence and other detectors — this attests the orphan-exec observation channel only",
        ],
    )


# --- the verdicts.jsonl store (beside findings.jsonl) --------------------------------------------


class VerdictsStore:
    """Append canon ``DetectionVerdict.to_contract()`` JSON objects to ``verdicts.jsonl``, one per
    line, beside ``findings.jsonl``. Deduped by the verdict's provenance cid (its content address),
    so re-running does not duplicate a verdict for the same underlying detection."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def existing_provenance(self) -> set[str]:
        if not self.path.exists():
            return set()
        seen: set[str] = set()
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    seen.add(json.loads(line)["provenance"])
                except (json.JSONDecodeError, KeyError, TypeError):
                    continue
        return seen

    def append_new(self, contracts: Iterable[dict]) -> list[dict]:
        existing = self.existing_provenance()
        new: list[dict] = []
        seen_this_batch: set[str] = set()
        for c in contracts:
            cid = c.get("provenance")
            if cid in existing or cid in seen_this_batch:
                continue
            new.append(c)
            seen_this_batch.add(cid)
        if new:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                for c in new:
                    fh.write(json.dumps(c, sort_keys=True) + "\n")
        return new
