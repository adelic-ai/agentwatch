"""Reconstruct a pid/ppid process tree from ground-truth exec + clone events (design doc §4)."""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Optional

from agentwatch.events import CLONE, EXEC, GroundTruthEvent


class ProcessTree:
    """pid -> ppid, and pid -> its own exec timestamps, built from a stream of ground-truth events.

    Ancestry edges (`pid -> ppid`) come from BOTH kinds:
      - EXEC events, authoritative for a process that ran a program;
      - CLONE events, which supply the edge for a forked process that may *never* execve. Without
        them a fork-then-orchestrate shell (Gemini's persistent shell tool) is an invisible hole,
        and the ancestry walk dies there, orphaning the whole subtree it spawned (the "fork gap").
    A CLONE edge never overrides an EXEC-derived ppid for the same pid and contributes no exec
    timestamp - it is structure only, not an action (see events.py's CLONE field convention).

    A pid can appear more than once (a process re-exec'ing itself, or - across a long enough log -
    pid reuse by the kernel); `exec_timestamps` keeps every occurrence rather than collapsing to
    one, since the reconciler needs "did *any* exec of this pid land inside the window", not just
    the first.
    """

    def __init__(self, ground_truth_events: Iterable[GroundTruthEvent]) -> None:
        self._ppid_of: dict[int, int] = {}
        self._exec_ts_by_pid: dict[int, list[float]] = defaultdict(list)
        self._uid_by_pid: dict[int, int] = {}
        for ev in ground_truth_events:
            if ev.pid is None:
                continue
            if ev.kind == EXEC:
                if ev.ppid is not None:
                    self._ppid_of[ev.pid] = ev.ppid
                self._exec_ts_by_pid[ev.pid].append(ev.ts)
                if ev.uid is not None:
                    self._uid_by_pid[ev.pid] = ev.uid
            elif ev.kind == CLONE and ev.ppid is not None:
                # Structural bridge edge only. `setdefault` + the exec-membership guard keep an
                # authoritative EXEC ppid winning regardless of event order: if this pid also
                # execve'd, that record owns the edge; a clone only fills a pid that never did.
                if ev.pid not in self._exec_ts_by_pid:
                    self._ppid_of.setdefault(ev.pid, ev.ppid)
        for ts_list in self._exec_ts_by_pid.values():
            ts_list.sort()

    def ppid(self, pid: int) -> Optional[int]:
        return self._ppid_of.get(pid)

    def exec_timestamps(self, pid: int) -> list[float]:
        return self._exec_ts_by_pid.get(pid, [])

    def uid(self, pid: int) -> Optional[int]:
        return self._uid_by_pid.get(pid)

    def ancestry(self, pid: int, max_depth: int = 128) -> list[int]:
        """[pid, ppid(pid), ppid(ppid(pid)), ...] - stops at a cycle, an unknown ppid, or max_depth.

        The chain includes `pid` itself first, since a process can be its own authorizing tool_use
        root (e.g. the shell a Bash tool_use spawned directly, not just its descendants).
        """
        chain = [pid]
        seen = {pid}
        current = pid
        for _ in range(max_depth):
            parent = self._ppid_of.get(current)
            if parent is None or parent in seen:
                break
            chain.append(parent)
            seen.add(parent)
            current = parent
        return chain
