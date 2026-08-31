"""eBPF (bpftrace) ground-truth adapter — the fused-evidence PRODUCER for decision B.

Unit-testable half: the parser. Loading the probe needs real kernel privilege (opuser / VM-root) and is
NOT exercised here. The last test is the money one — the full chain: bpftrace text -> parser ->
cgroup-labeled GroundTruthEvents -> the reconciler's cgroup-keyed scoping -> the fork gap closes.
"""
import unittest

from agentwatch.events import CLONE, EXEC
from agentwatch.groundtruth import ebpf
from agentwatch.reconciler.orphan import reconcile_orphans_scoped
from agentwatch.reconciler.verdict import Verdict

AGENT_UID = 1000
RUNTIME_EXE = "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"
CONTAINER_CG = "12345"  # the container's cgroup id, shared by everything in it


class ParseContract(unittest.TestCase):
    def test_exec_line_parses_with_cgroup(self) -> None:
        line = f"E\t100000000000\t5000\t4999\t1000\t{CONTAINER_CG}\tEXP_EXT\t/tmp/EXP_EXT"
        events, stats = ebpf.parse_lines([line])
        self.assertEqual(len(events), 1)
        e = events[0]
        self.assertEqual((e.kind, e.pid, e.ppid, e.uid, e.comm, e.exe), (EXEC, 5000, 4999, 1000, "EXP_EXT", "/tmp/EXP_EXT"))
        self.assertEqual(e.cgroup, CONTAINER_CG)   # the field the fork-gap rescue keys on
        self.assertEqual(e.ts, 100.0)              # ns -> s
        self.assertEqual(e.source, "ebpf")
        self.assertEqual(stats.events_emitted, 1)

    def test_fork_line_parses_as_clone_child_over_parent(self) -> None:
        # CLONE convention: pid = created child, ppid = caller/parent.
        events, _ = ebpf.parse_lines([f"F\t50000000000\t5000\t4999\t1000\t{CONTAINER_CG}\tsh"])
        self.assertEqual((events[0].kind, events[0].pid, events[0].ppid), (CLONE, 5000, 4999))
        self.assertEqual(events[0].cgroup, CONTAINER_CG)

    def test_banner_and_malformed_lines_are_skipped_not_errored(self) -> None:
        events, stats = ebpf.parse_lines(["Attaching 2 probes...", "", "garbage line", "E\ttoo\tfew"])
        self.assertEqual(events, [])
        self.assertEqual(stats.events_emitted, 0)
        self.assertGreaterEqual(stats.lines_total, 3)

    def test_end_to_end_ebpf_cgroup_evidence_closes_the_fork_gap(self) -> None:
        # A real agent session, plus an exec injected by a fork-without-exec parent (pid 4999, no exec
        # record) — the fork gap. Both carry the container cgroup, exactly as the eBPF program emits it.
        runtime_line = f"E\t100000000000\t1000\t1\t{AGENT_UID}\t{CONTAINER_CG}\tnode\t{RUNTIME_EXE}"
        injected_line = f"E\t200000000000\t5000\t4999\t{AGENT_UID}\t{CONTAINER_CG}\tEXP_EXT\t/tmp/EXP_EXT"

        events, _ = ebpf.parse_lines([runtime_line, injected_line])
        candidates = reconcile_orphans_scoped(events, transcript_events=[], agent_uid=AGENT_UID)

        injected = [c for c in candidates if c.event.pid == 5000]
        self.assertTrue(injected, "the injected exec must appear as a candidate")
        self.assertEqual(
            injected[0].verdict, Verdict.CONFIRMED,
            "eBPF-supplied cgroup evidence must let the reconciler adjudicate the fork-gap exec "
            "(CONFIRMED), not leave it UNEVALUABLE — this is the whole producer->consumer chain.",
        )


if __name__ == "__main__":
    unittest.main()
