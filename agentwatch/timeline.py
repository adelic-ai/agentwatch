"""Merge transcript events + findings + git commits into one time-ordered timeline.

Design doc §5: "Peek and History are one viewer (parsed jsonl) at different scope, and claudescope
already is that viewer... the only extension worth making: overlay the detector's findings and the
work repo's git commits onto that same parsed-transcript timeline, so 'what it did', 'what it
produced', and 'what was flagged' read as one view."

This module is the merge/data layer for that overlay; `web/render_timeline.py` is the thin
renderer on top of it. See DECISIONS.md for why a renderer needed writing at all - claudescope's
`web/` turned out to hold static write-ups, not a live timeline component to extend in place.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

from agentwatch.events import NormalizedEvent
from agentwatch.findings import Finding

TRANSCRIPT = "transcript"
FINDING = "finding"
COMMIT = "commit"


@dataclass(frozen=True)
class CommitInfo:
    sha: str
    ts: float
    author: str
    subject: str


@dataclass(frozen=True)
class TimelineItem:
    ts: float
    kind: str  # TRANSCRIPT | FINDING | COMMIT
    detail: dict


def commits_from_git_log(repo_path) -> List[CommitInfo]:
    """`git log` over `repo_path`, oldest-unbounded. Never raises - an unreadable/non-git repo
    just contributes no commits to the overlay rather than breaking the whole timeline render."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "log", "--format=%H%x1f%ct%x1f%an%x1f%s"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    commits = []
    for line in result.stdout.splitlines():
        parts = line.split("\x1f")
        if len(parts) != 4:
            continue
        sha, ts_raw, author, subject = parts
        try:
            ts = float(ts_raw)
        except ValueError:
            continue
        commits.append(CommitInfo(sha=sha, ts=ts, author=author, subject=subject))
    return commits


def build_timeline(
    transcript_events: Iterable[NormalizedEvent],
    findings: Iterable[Finding],
    commits: Iterable[CommitInfo],
) -> List[TimelineItem]:
    """One ts-sorted list mixing all three sources - the overlay itself."""
    items: List[TimelineItem] = []

    for e in transcript_events:
        items.append(
            TimelineItem(
                ts=e.ts,
                kind=TRANSCRIPT,
                detail={
                    "event_kind": e.kind,
                    "tool_name": e.tool_name,
                    "tool_input": e.tool_input,
                    "text": e.text,
                    "session_id": e.session_id,
                },
            )
        )

    for f in findings:
        items.append(
            TimelineItem(
                ts=f.ts,
                kind=FINDING,
                detail={
                    "id": f.id,
                    "detector": f.detector,
                    "summary": f.summary,
                    "evidence": f.evidence,
                    "session_id": f.session_id,
                },
            )
        )

    for c in commits:
        items.append(
            TimelineItem(
                ts=c.ts,
                kind=COMMIT,
                detail={"sha": c.sha, "author": c.author, "subject": c.subject},
            )
        )

    items.sort(key=lambda i: i.ts)
    return items
