"""Self-modification detector (design doc §3.5, §2's input list).

Unlike the other detectors, this one is inherently stateful: "a change to the agent's own config"
can only be judged against a *previous* value, so this compares a content-hash baseline (captured
on a prior run and persisted by the caller - see cli.py) against the current file content. A path
with no baseline entry yet is not a finding - that's the baseline-establishing run, not a
detected change - it just seeds `update_baseline()`'s output for next time.

Watches exactly the paths design doc §2 names as the agent's own config surface: settings.json
(hooks), CLAUDE.md, and .claude.json (MCP config).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

DEFAULT_WATCHED_PATHS: tuple[str, ...] = (
    "~/.claude/settings.json",
    "~/.claude/CLAUDE.md",
    "~/.claude.json",
)


@dataclass(frozen=True)
class SelfModCandidate:
    path: str
    baseline_hash: Optional[str]
    current_hash: Optional[str]
    is_change: bool
    exists: bool


def _hash_file(path: Path) -> Optional[str]:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return hashlib.sha256(data).hexdigest()


def check_self_modification(
    baseline: dict, watched_paths: Iterable[str] = DEFAULT_WATCHED_PATHS
) -> list[SelfModCandidate]:
    """Compare current file hashes against `baseline` (path -> sha256 hex, or None if absent then).

    A path missing from `baseline` entirely is treated as "no prior observation" (not a change) -
    distinct from a path that *was* observed as absent (baseline_hash=None) and now exists, which
    genuinely is a change worth flagging (a config file being created where none existed is itself
    self-modification).
    """
    results = []
    for raw_path in watched_paths:
        path = Path(raw_path).expanduser()
        current_hash = _hash_file(path)
        has_baseline = raw_path in baseline
        baseline_hash = baseline.get(raw_path)
        is_change = has_baseline and current_hash != baseline_hash
        results.append(
            SelfModCandidate(
                path=raw_path,
                baseline_hash=baseline_hash,
                current_hash=current_hash,
                is_change=is_change,
                exists=path.exists(),
            )
        )
    return results


def update_baseline(candidates: Iterable[SelfModCandidate]) -> dict:
    """The new baseline to persist after this run - always advances to current, changed or not."""
    return {c.path: c.current_hash for c in candidates}
