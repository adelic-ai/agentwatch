"""Parse-health / drift-gating (design doc v2 §4).

The self-report plane (transcript) drifts across Claude Code versions; the ground-truth plane
(auditd) doesn't. If a schema change silently makes the adapter extract fewer tool_use events -
without raising, since it's defensive by design (see adapters/claude_code.py) - the orphan
reconciler would read that as "fewer authorizing tool_use exist" and produce *more* false
CONFIRMED orphans, exactly backwards from what a parse failure should do. This module is the
safety net: two independent, complementary sanity checks, either of which alone means "don't trust
this transcript enough to confirm an orphan from it."

  skip-rate       - the fraction of transcript lines the adapter couldn't extract anything from.
                    A version bump that renames a field doesn't crash the parser (by design), it
                    just makes lines look "uninteresting" - skip-rate is what catches that.
  tool_use craters - execs are plentiful (the agent is clearly doing things) but the transcript
                    yields ~no tool_use at all. Either the agent used no tools at all in a real
                    exec-heavy run (implausible) or extraction broke.

Either signal alone sets `degraded=True`. A caller (run.py) responds per design doc v2 §4: surface
this as its own finding, and downgrade every orphan verdict that would have been CONFIRMED to NONE
(reconciler/orphan.py:reconcile_orphans_scoped's `degraded` flag) - unreliable self-report must
never yield a false CONFIRMED, whether it's lying or just version-broken.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from agentwatch.adapters.claude_code import KNOWN_VERSIONS
from agentwatch.events import ParseStats

# A version bump alone isn't proof of drift (this build has only ever seen one version's real
# data), so it doesn't set `degraded` by itself - it's carried in `reasons` as context if one of
# the two structural checks below also fires, and ignored (silently) otherwise.
SKIP_RATE_THRESHOLD = 0.2
# Below this many ground-truth execs, "zero tool_use" is unremarkable (a short/quiet run) rather
# than a sign of broken extraction - the sanity check needs enough exec volume to be meaningful.
MIN_EXEC_FOR_SANITY_CHECK = 10


@dataclass(frozen=True)
class ParseHealth:
    skip_rate: float
    tool_use_count: int
    exec_count: int
    unknown_version: bool
    degraded: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)


def assess_parse_health(
    stats: ParseStats,
    tool_use_count: int,
    exec_count: int,
    known_versions: frozenset = KNOWN_VERSIONS,
) -> ParseHealth:
    skip_rate = (stats.lines_skipped / stats.lines_total) if stats.lines_total else 0.0
    unknown_version = bool(stats.versions_seen) and not (
        set(stats.versions_seen) & known_versions
    )

    reasons: list[str] = []
    degraded = False

    if skip_rate > SKIP_RATE_THRESHOLD:
        degraded = True
        reasons.append(
            f"skip-rate {skip_rate:.0%} exceeds {SKIP_RATE_THRESHOLD:.0%} "
            f"({stats.lines_skipped}/{stats.lines_total} lines; top reasons: {stats.skip_reasons})"
        )

    if exec_count >= MIN_EXEC_FOR_SANITY_CHECK and tool_use_count == 0:
        degraded = True
        reasons.append(
            f"tool_use count is 0 while {exec_count} ground-truth execs exist - "
            "extraction likely broken, not a genuinely tool-free run"
        )

    if unknown_version:
        reasons.append(f"transcript version(s) {sorted(stats.versions_seen)} not in KNOWN_VERSIONS")

    return ParseHealth(
        skip_rate=skip_rate,
        tool_use_count=tool_use_count,
        exec_count=exec_count,
        unknown_version=unknown_version,
        degraded=degraded,
        reasons=tuple(reasons),
    )
