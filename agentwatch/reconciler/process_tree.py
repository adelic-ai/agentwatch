"""Reconstruct a pid/ppid process tree from ground-truth exec events (design doc §4)."""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Optional

from agentwatch.events import EXEC, GroundTruthEvent


class ProcessTree:
    """pid -> ppid, and pid -> its own exec timestamps, built from a stream of exec events.

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
            if ev.kind != EXEC or ev.pid is None:
                continue
            if ev.ppid is not None:
                self._ppid_of[ev.pid] = ev.ppid
            self._exec_ts_by_pid[ev.pid].append(ev.ts)
            if ev.uid is not None:
                self._uid_by_pid[ev.pid] = ev.uid
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
