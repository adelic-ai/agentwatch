"""Spawn the bpftrace probe and turn its output into GroundTruthEvents — decision B's loader=reader.

Under decision B (warden `REFACTOR.md`), agentwatch owns capture: the component that LOADS the eBPF
probe is the one that READS its buffer, so there is no warden-collector↔agentwatch-reconciler seam to
diverge — the fork-gap failure mode is impossible by construction rather than merely caught by a test.
This module is that loader/reader. It builds the `bpftrace` invocation for `ebpf.BPFTRACE_PROGRAM`,
runs it for a bounded window, and feeds the output through `ebpf.parse_lines`.

**Privilege is caller-supplied — this module never elevates itself.** Loading an eBPF program needs
`CAP_BPF`/root, but the elevation decision (warden's scoped `sudo -n bpftrace`, or `()` when already
root on the vantage) lives in ONE audited place — `warden/privilege.py` — and is passed in as
`elevation_prefix`. Scattering `sudo` into agentwatch would make the privilege surface un-auditable and
couple the monitor to one host's sudo policy. So agentwatch describes *what to run*; warden decides
*with what privilege*, exactly as it already does for `auditctl`/`ausearch`.

Batch, not streaming — matching agentwatch's batch/poll design (README "Batch/poll, not real-time
streaming — by design"). `run_capture` runs the probe for `duration_s` and parses the whole window; a
live-streaming generator variant is a later addition for a real-time monitor, not needed for reconcile.
"""
from __future__ import annotations

import subprocess
from typing import Callable, Optional, Sequence

from agentwatch.events import GroundTruthEvent, ParseStats
from agentwatch.groundtruth.ebpf import bpftrace_argv, parse_lines

#: Default capture window. A reconcile pass wants a bounded, terminating run, not an open-ended stream;
#: the caller overrides for a longer session. `timeout(1)` is what bounds it (see `capture_argv`).
DEFAULT_CAPTURE_SECONDS = 30


class EbpfCaptureError(RuntimeError):
    """bpftrace exited non-zero for a reason OTHER than the capture-window timeout, and produced no
    events — e.g. the program failed to load (a BTF/verifier/permission error names itself on stderr).
    Distinct from an empty-but-clean capture (a quiet window), which is not an error."""


def capture_argv(
    elevation_prefix: Sequence[str] = (), duration_s: Optional[int] = None
) -> list[str]:
    """The full argv to run the probe: `[<elevation>] [timeout <n>] bpftrace -e <program>`.

    `timeout(1)` bounds the run so a batch capture terminates on its own; without it bpftrace streams
    until killed. `elevation_prefix` (e.g. `("sudo", "-n")`) is prepended so the WHOLE pipeline —
    `timeout` included — runs with the privilege bpftrace needs. Order matters: elevation wraps
    `timeout` wraps `bpftrace`, so the kill signal reaches the privileged child.
    """
    argv = list(bpftrace_argv())
    if duration_s is not None:
        argv = ["timeout", str(int(duration_s)), *argv]
    return [*elevation_prefix, *argv]


def parse_capture_output(stdout: str) -> tuple[list[GroundTruthEvent], ParseStats]:
    """bpftrace stdout -> normalized events. A thin wrapper over `ebpf.parse_lines` kept here so the
    capture path has one obvious entry point; the banner and exit-time map dump are skipped there."""
    return parse_lines(stdout.splitlines())


def run_capture(
    *,
    duration_s: Optional[int] = DEFAULT_CAPTURE_SECONDS,
    elevation_prefix: Sequence[str] = (),
    _run: Callable = subprocess.run,
) -> tuple[list[GroundTruthEvent], ParseStats]:
    """Run the probe for `duration_s` and return its parsed events + parse stats.

    Terminal-state handling is deliberate, because the *normal* end of a bounded capture looks like a
    failure to a naive check:
      - rc 0   — bpftrace exited cleanly (rare for a timed run, but valid).
      - rc 124 — `timeout` killed bpftrace at the window's end. This is the EXPECTED terminal state of
                 a batch capture, NOT an error; whatever landed on stdout up to that point is the run.
      - other  — a genuine failure (program didn't load, no privilege). If it also produced no events,
                 raise `EbpfCaptureError` with stderr rather than silently reporting an empty plane —
                 an unproven-capture-reported-as-clean is exactly the failure this stack exists to avoid.
                 If it somehow produced events anyway, return them (a partial capture beats none).
    """
    argv = capture_argv(elevation_prefix, duration_s)
    proc = _run(argv, capture_output=True, text=True)
    events, stats = parse_capture_output(proc.stdout or "")
    if proc.returncode not in (0, 124) and not events:
        stderr = (proc.stderr or "").strip()
        raise EbpfCaptureError(
            f"bpftrace capture failed (rc={proc.returncode}) and produced no events: "
            f"{stderr[:500] or '<no stderr>'}"
        )
    return events, stats
