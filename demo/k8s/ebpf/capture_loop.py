"""DaemonSet entrypoint: loop `ebpf_capture.run_capture`, append each window's events as JSONL to
a hostPath-mounted file (K8S-DESIGN.md §4 - "ships events to the central reconciler", file-based
transport, same decision already made for the K8s audit log adapter). No capture-logic changes -
this is packaging only, `agentwatch/groundtruth/ebpf_capture.py`/`ebpf.py` are used unmodified.

Runs as root inside a privileged container (this Dockerfile's whole reason to exist) - per
ebpf_capture.py's own doc, "() when already root", so elevation_prefix is empty here, same as
warden's vantage path uses when already root on the VM.
"""
from __future__ import annotations

import dataclasses
import json
import os
import sys
import time

sys.path.insert(0, "/opt/agentwatch")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agentwatch.groundtruth.ebpf_capture import EbpfCaptureError, run_capture
from pod_lookup import CgroupSubjectResolver

OUTPUT_PATH = os.environ.get("EBPF_OUTPUT_PATH", "/var/log/agentwatch-ebpf/events.jsonl")
NODE_NAME = os.environ.get("NODE_NAME", "unknown-node")
WINDOW_SECONDS = int(os.environ.get("EBPF_WINDOW_SECONDS", "10"))


def main() -> None:
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    print(f"[capture_loop] starting on node={NODE_NAME}, window={WINDOW_SECONDS}s, "
          f"output={OUTPUT_PATH}", flush=True)
    resolver = CgroupSubjectResolver(NODE_NAME)
    while True:
        resolver.refresh()  # once per window, not per event - see pod_lookup.py's docstring
        try:
            events, stats = run_capture(duration_s=WINDOW_SECONDS, elevation_prefix=())
        except EbpfCaptureError as exc:
            print(f"[capture_loop] capture failed: {exc}", flush=True)
            time.sleep(WINDOW_SECONDS)
            continue
        resolved = 0
        if events:
            with open(OUTPUT_PATH, "a", encoding="utf-8") as fh:
                for ev in events:
                    row = dataclasses.asdict(ev)
                    row["node"] = NODE_NAME
                    if ev.cgroup is not None:
                        try:
                            subject_id = resolver.subject_for(int(ev.cgroup))
                        except ValueError:
                            subject_id = None
                        if subject_id is not None:
                            row["subject_id"] = subject_id
                            resolved += 1
                    fh.write(json.dumps(row) + "\n")
        print(f"[capture_loop] window done: {len(events)} events, {resolved} resolved to a "
              f"subject_id, {stats.lines_total} lines read, "
              f"{sum(stats.skip_reasons.values())} skipped", flush=True)


if __name__ == "__main__":
    main()
