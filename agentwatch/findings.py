"""Finding model + findings.jsonl store (design doc §3, §5).

A Finding is what every detector converges to. Each carries a deterministic `id` - a hash of the
detector name plus the fields that identify *this* occurrence - so the same underlying event
always produces the same id across separate runs. That's what makes findings.jsonl safely
append-only-with-dedup, and what lets the notifier report only genuinely new findings each pass:
"surfaced to the human once (deduped)" (design doc §3).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Iterable, List, Optional

DETECTOR_ORPHAN_SYSCALL = "orphan_syscall"
DETECTOR_DIVERGENCE = "divergence"
DETECTOR_LAN_REACH = "lan_reach"
DETECTOR_SELF_MOD = "self_mod"
DETECTOR_AGENT_FLAG = "agent_flag"
DETECTOR_LETHAL_TRIFECTA = "lethal_trifecta"  # stub only in v1 - see reconciler/trifecta.py
DETECTOR_PARSE_HEALTH = "parse_health"  # v2, design doc v2 §4 - see reconciler/parse_health.py
# A COVERAGE finding, not a behaviour one: execs the reconciler could not evaluate at all. Kept
# separate from orphan_syscall on purpose - conflating "I looked and this is unexplained" with "I
# could not look" is exactly what DECISIONS.md G24 exists to stop.
DETECTOR_UNEVALUABLE = "unevaluable_exec"

# Detectors whose findings derive from the GROUND-TRUTH plane, so they inherit that plane's
# substrate trust tier (CONTRACT.md §4 / contract.py PlaneTrust). Transcript-plane findings
# (divergence, parse_health) and the filesystem/flag findings (self_mod, agent_flag) are NOT here:
# the ground-truth plane does not vouch for them, so stamping a trust tier on them would be a false
# claim. lethal_trifecta is a transcript-plane stub -> excluded.
GROUND_TRUTH_DETECTORS = frozenset({
    DETECTOR_ORPHAN_SYSCALL,
    DETECTOR_LAN_REACH,
    DETECTOR_UNEVALUABLE,
})


def _make_id(detector: str, *key_parts: object) -> str:
    """A stable short hash over whatever fields make this occurrence unique to its detector."""
    raw = detector + "\x1f" + "\x1f".join(str(p) for p in key_parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class Finding:
    id: str
    detector: str
    ts: float
    summary: str
    evidence: dict = field(default_factory=dict)
    session_id: Optional[str] = None
    # The substrate trust tier of the ground-truth plane this finding derives from (a PlaneTrust
    # value, CONTRACT.md §4), or None when undeclared / not ground-truth-derived. Deliberately NOT
    # part of `id` (see stamp_plane_trust): a finding's identity is the event it describes, not the
    # operator's trust declaration. Optional with a default so old findings.jsonl lines (written
    # before this field existed) still load via from_json.
    plane_trust: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @staticmethod
    def from_json(line: str) -> "Finding":
        d = json.loads(line)
        return Finding(**d)


def stamp_plane_trust(findings: Iterable["Finding"], tier: Optional[str]) -> List["Finding"]:
    """Stamp the ground-truth substrate trust tier (CONTRACT.md §4) onto the findings that derive
    from the ground-truth plane (GROUND_TRUTH_DETECTORS). Transcript-plane and filesystem findings
    are left untouched - the ground-truth plane does not vouch for them.

    `tier` is a PlaneTrust *value* (str) or None. None leaves every finding unstamped - the honest
    default when the operator has not declared the substrate. Applied AFTER id computation, so a
    finding's identity and its dedup are independent of the declared tier (the same orphan is the
    same finding whether the plane was declared unforgeable or not; the tier is metadata about how
    much to trust it, not part of what it is).
    """
    if tier is None:
        return list(findings)
    return [
        replace(f, plane_trust=tier) if f.detector in GROUND_TRUTH_DETECTORS else f
        for f in findings
    ]


# --- per-detector Finding constructors ----------------------------------------------------------
# Each detector module returns its own candidate/event shape (kept rich, for the "log suppressed
# candidates" auditability design doc §3 asks for); these functions are the one place that shape
# gets flattened into the common Finding the store/notifier/UI actually deal with.


def orphan_finding(candidate) -> Finding:
    """Only call this for a CONFIRMED-verdict candidate (see run.py) - `evidence["verdict"]` is
    recorded for audit completeness, but a NONE/None-verdict candidate should never reach here."""
    ev = candidate.event
    fid = _make_id(
        DETECTOR_ORPHAN_SYSCALL, ev.pid, ev.ppid, ev.ts, ev.exe, tuple(candidate.ancestry_checked)
    )
    summary = f"orphan exec: pid={ev.pid} exe={ev.exe} comm={ev.comm} - no ancestor tool_use in window"
    evidence = {
        "pid": ev.pid,
        "ppid": ev.ppid,
        "uid": ev.uid,
        "exe": ev.exe,
        "comm": ev.comm,
        "args": list(ev.args),
        "ancestry_checked": list(candidate.ancestry_checked),
        "source": ev.source,
        "verdict": candidate.verdict.value if candidate.verdict else None,
        "reason": candidate.reason,
    }
    return Finding(id=fid, detector=DETECTOR_ORPHAN_SYSCALL, ts=ev.ts, summary=summary, evidence=evidence)


def divergence_finding(candidate) -> Finding:
    r_ev = candidate.reasoning_event
    a_ev = candidate.actual_tool_use
    fid = _make_id(DETECTOR_DIVERGENCE, r_ev.uuid, a_ev.uuid, candidate.stated_tools, a_ev.tool_name)
    stated = "/".join(candidate.stated_tools)
    summary = f"stated {stated}, actually called {a_ev.tool_name}"
    evidence = {
        "reasoning_text": r_ev.text,
        "stated_tools": list(candidate.stated_tools),
        "actual_tool": a_ev.tool_name,
        "actual_tool_input": a_ev.tool_input,
    }
    return Finding(
        id=fid,
        detector=DETECTOR_DIVERGENCE,
        ts=a_ev.ts,
        summary=summary,
        evidence=evidence,
        session_id=a_ev.session_id,
    )


def lan_reach_finding(ev) -> Finding:
    message = ev.raw.get("MESSAGE") if isinstance(ev.raw, dict) else None
    fid = _make_id(DETECTOR_LAN_REACH, ev.ts, ev.pid, message)
    summary = f"LAN-reach attempt blocked: pid={ev.pid} comm={ev.comm}"
    evidence = {"pid": ev.pid, "comm": ev.comm, "raw_message": message}
    return Finding(id=fid, detector=DETECTOR_LAN_REACH, ts=ev.ts, summary=summary, evidence=evidence)


def self_mod_finding(candidate, ts: float) -> Finding:
    fid = _make_id(DETECTOR_SELF_MOD, candidate.path, candidate.baseline_hash, candidate.current_hash)
    summary = f"self-modification: {candidate.path} changed since baseline"
    evidence = {
        "path": candidate.path,
        "baseline_hash": candidate.baseline_hash,
        "current_hash": candidate.current_hash,
    }
    return Finding(id=fid, detector=DETECTOR_SELF_MOD, ts=ts, summary=summary, evidence=evidence)


def agent_flag_finding(entry, ts: float) -> Finding:
    fid = _make_id(DETECTOR_AGENT_FLAG, entry.raw)
    summary = f"NEEDS-HUMAN.md: {entry.heading}"
    evidence = {"heading": entry.heading, "body": entry.body}
    return Finding(id=fid, detector=DETECTOR_AGENT_FLAG, ts=ts, summary=summary, evidence=evidence)


def unevaluable_finding(candidates, ts: float) -> Finding:
    """ONE aggregate finding for a run's unevaluable execs (DECISIONS.md G24), never one each.

    A per-exec finding would put a coverage defect in the same stream as agent behaviour and, on a
    run that shells out repeatedly, bury the behaviour findings under it. The failure being
    reported is a property of the run's ground-truth plane, not of any single process - so it is
    reported once, with the processes listed as evidence.

    Deliberately NOT severity-graded down to nothing: a run that cannot see what the agent executed
    is a weaker run, and the number belongs next to the CONFIRMED count rather than in a debug log.
    """
    pids = sorted({c.event.pid for c in candidates if c.event.pid is not None})
    comms = sorted({c.event.comm for c in candidates if c.event.comm})
    fid = _make_id(DETECTOR_UNEVALUABLE, ts, tuple(pids))
    summary = (
        f"{len(candidates)} agent-uid exec(s) could not be evaluated - ancestry breaks at a "
        f"process that forked without exec'ing ({', '.join(comms) if comms else 'unknown comm'}). "
        "Neither authorized nor unexplained: not examined."
    )
    evidence = {
        "count": len(candidates),
        "pids": pids,
        "comms": comms,
        "execs": [
            {
                "pid": c.event.pid,
                "ppid": c.event.ppid,
                "comm": c.event.comm,
                "exe": c.event.exe,
                "ts": c.event.ts,
                "ancestry_checked": list(c.ancestry_checked),
                "reason": c.reason,
            }
            for c in candidates
        ],
    }
    return Finding(
        id=fid, detector=DETECTOR_UNEVALUABLE, ts=ts, summary=summary, evidence=evidence
    )


def parse_health_finding(health, ts: float) -> Finding:
    """Design doc v2 §4: surface degraded transcript extraction as its own finding, distinct from
    (and alongside) downgrading orphan verdicts to NONE for the same run."""
    fid = _make_id(DETECTOR_PARSE_HEALTH, ts, health.skip_rate, health.tool_use_count, health.exec_count)
    summary = "transcript parser degraded - likely a Claude Code version change: " + "; ".join(health.reasons)
    evidence = {
        "skip_rate": health.skip_rate,
        "tool_use_count": health.tool_use_count,
        "exec_count": health.exec_count,
        "unknown_version": health.unknown_version,
        "reasons": list(health.reasons),
    }
    return Finding(id=fid, detector=DETECTOR_PARSE_HEALTH, ts=ts, summary=summary, evidence=evidence)


class FindingsStore:
    """Append-only findings.jsonl with id-based dedup."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def existing_ids(self) -> set[str]:
        if not self.path.exists():
            return set()
        ids: set[str] = set()
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ids.add(json.loads(line)["id"])
                except (json.JSONDecodeError, KeyError, TypeError):
                    continue
        return ids

    def all(self) -> list[Finding]:
        if not self.path.exists():
            return []
        findings = []
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(Finding.from_json(line))
                except (json.JSONDecodeError, TypeError):
                    continue
        return findings

    def append_new(self, findings: Iterable[Finding]) -> list[Finding]:
        """Append findings not already on disk (by id). Returns only the newly-written ones -
        that return value is what a notifier should report; everything else already ran once."""
        existing = self.existing_ids()
        new_findings: list[Finding] = []
        seen_this_batch: set[str] = set()
        for f in findings:
            if f.id in existing or f.id in seen_this_batch:
                continue
            new_findings.append(f)
            seen_this_batch.add(f.id)
        if new_findings:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                for f in new_findings:
                    fh.write(f.to_json() + "\n")
        return new_findings
