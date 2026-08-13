"""eBPF (bpftrace) process-lifecycle parser -> normalized GroundTruthEvent stream.

The fused-evidence PRODUCER for decision B (warden `CANONICAL-SHAPE.md` / `REFACTOR.md`): where auditd
emits `execve` to a shared log, this attaches an eBPF program to the kernel's `sched_process_{exec,fork}`
tracepoints and captures EVERY process creation — including the fork-without-exec and host-root
injections that auditd's uid-scoped execve rule misses — WITH the **cgroup** attached. The cgroup is the
fork-gap-robust membership key the reconciler's cgroup-keyed scoping (`runtime_scope.py`) consumes.

This module is the **parser** (unit-testable, unprivileged) plus the program text and the command to run
it. Actually *loading* the probe needs `CAP_BPF`/root on a kernel you own — the one piece that must
validate on real hardware (gembox / a VM-root), never in the unprivileged container. `bpftrace` is a
runtime dependency (like auditd for `audit_log.py`); this module never imports or spawns it.

Output contract (`BPFTRACE_PROGRAM`'s printf, TAB-delimited, one event per line):

    E \t <ts_ns> \t <pid> \t <ppid> \t <uid> \t <cgroup_id> \t <comm> \t <filename>   (exec)
    F \t <ts_ns> \t <child_pid> \t <parent_pid> \t <uid> \t <cgroup_id> \t <comm>      (fork / clone)

`nsecs` is boot-relative; the reconciler's internal scope comparisons (`runtime_first_ts` vs event `ts`)
share this clock so they are correct. Aligning against the transcript's wall-clock window is a boot-offset
detail handled at capture time (documented, not hidden).
"""
from __future__ import annotations

from typing import Iterable, Optional

from agentwatch.events import CLONE, EXEC, GroundTruthEvent, ParseStats

# The eBPF program, in bpftrace. `cgroup` is the current process's cgroup id — the key the cgroup rescue
# needs. The exact field accesses (`curtask->real_parent->tgid`, `str(args->filename)`) rely on BTF and
# MUST be validated on a real kernel; the parser below is what is unit-tested here.
BPFTRACE_PROGRAM = r"""
tracepoint:sched:sched_process_exec {
    printf("E\t%llu\t%d\t%d\t%d\t%llu\t%s\t%s\n",
           nsecs, pid, curtask->real_parent->tgid, uid, cgroup, comm, str(args->filename));
}
tracepoint:sched:sched_process_fork {
    printf("F\t%llu\t%d\t%d\t%d\t%llu\t%s\n",
           nsecs, args->child_pid, args->parent_pid, uid, cgroup, comm);
}
"""


def bpftrace_argv() -> list[str]:
    """The command a *privileged* caller runs to stream the contract above (needs root/CAP_BPF).
    Kept here so the program and its invocation stay together; this module never spawns it."""
    return ["bpftrace", "-e", BPFTRACE_PROGRAM]


def _int(value: str) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _ns_to_s(raw: str) -> float:
    return (_int(raw) or 0) / 1_000_000_000.0


def parse_lines(lines: Iterable[str]) -> tuple[list[GroundTruthEvent], ParseStats]:
    """Parse bpftrace output (the contract above) into GroundTruthEvents. Never raises on a bad line;
    bpftrace's own banner/stat lines and any malformed record are skipped, not errored."""
    stats = ParseStats()
    events: list[GroundTruthEvent] = []
    for raw_line in lines:
        stats.lines_total += 1
        line = raw_line.rstrip("\n")
        if not line:
            continue
        fields = line.split("\t")
        marker = fields[0]

        if marker == "E" and len(fields) >= 8:
            ts_ns, pid, ppid, uid, cgroup, comm, filename = fields[1:8]
            events.append(GroundTruthEvent(
                ts=_ns_to_s(ts_ns), kind=EXEC,
                pid=_int(pid), ppid=_int(ppid), uid=_int(uid),
                comm=comm or None, exe=filename or None,
                cgroup=cgroup or None, source="ebpf", raw=line,
            ))
            stats.events_emitted += 1
        elif marker == "F" and len(fields) >= 7:
            # CLONE convention (events.py): pid = created child, ppid = the caller (parent).
            ts_ns, child, parent, uid, cgroup, comm = fields[1:7]
            events.append(GroundTruthEvent(
                ts=_ns_to_s(ts_ns), kind=CLONE,
                pid=_int(child), ppid=_int(parent), uid=_int(uid),
                comm=comm or None, cgroup=cgroup or None, source="ebpf", raw=line,
            ))
            stats.events_emitted += 1
        else:
            # bpftrace prints "Attaching N probes..." and may print map dumps on exit — not events.
            stats.record_skip("not_an_event_line")
    return events, stats
