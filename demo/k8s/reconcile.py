"""Reconcile real K8s ground truth against real Warrant grants (K8S-DESIGN.md §6/§8).

Validated for real, 2026-08-30/31, against a live `kind` cluster + in-cluster warrant on pop-os:
the authorized ConfigMap read produces no finding; the unauthorized Secret-create produces
`CONFIRMED` (technique `k8s_scope_violation`). Along the way this run caught a real bug (fixed,
see agentwatch/adapters/warrant.py's docstring and git history) that all 37 unit tests from the
original build missed, because their fixtures never used warrant's actual offset-less wire
timestamp shape - a live run is not optional, unit tests alone did not prove this worked.

`--ebpf-events` folds in the eBPF DaemonSet's captured process execs too (K8S-DESIGN.md §5,
`ebpf/`), reconciled through the exact same path as K8s API actions via
`reconciler.k8s_scope.exec_events_as_actions` - a raw exec becomes a
`(action="exec", resource="process:<name>")` candidate, checked against a Warrant grant of that
same shape. The eBPF JSONL stamps `subject_id` per row (capture_loop.py's own resolution, via
pod_lookup.py) - `run.py`'s loader deliberately ignores that field (identity there is a caller-
supplied contract, not something a JSONL row gets to assert for itself - see
`agentwatch/run.py`'s `_load_ebpf_events` docstring), so this script rebuilds a `cgroup_id ->
subject_id` map from the same file and passes it in explicitly, same shape either way.

Usage, after `kind-config.yaml` + `warrant-deploy.yaml` + `demo-agent-rbac.yaml` +
`demo-agent-pod.yaml` (and, optionally, `ebpf/rbac.yaml` + `ebpf/daemonset.yaml`) are applied:

    kubectl port-forward svc/warrant 18000:8000 &
    python3 reconcile.py [--audit-log PATH] [--ebpf-events PATH] [--warrant-url URL] [--filter SUBSTRING]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agentwatch.adapters.warrant import WarrantGrantAdapter
from agentwatch.run import Config, run_once


def _cgroup_to_subject_from_ebpf_file(path: Path) -> dict:
    """Rebuild {cgroup_id: subject_id} from capture_loop.py's own stamped rows - the DaemonSet is
    the thing that actually knows this binding (K8S-DESIGN.md §3), so this script trusts its
    output rather than re-deriving it. Malformed/unstamped rows are skipped, not fatal."""
    mapping: dict = {}
    if not path.exists():
        return mapping
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            cgroup, subject = row.get("cgroup"), row.get("subject_id")
            if cgroup and subject:
                mapping[cgroup] = subject
    return mapping


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--audit-log", type=Path, default=Path.home() / "k8s-audit/logs/audit.log")
    p.add_argument("--ebpf-events", type=Path, default=None,
                    help="e.g. path from `docker exec <node> cat /var/log/agentwatch-ebpf/events.jsonl` "
                         "saved locally - see ebpf/README notes on hostPath not being extraMounted out")
    p.add_argument("--warrant-url", default="http://127.0.0.1:18000")
    p.add_argument("--run-dir", type=Path, default=Path.home() / "k8s-audit")
    p.add_argument("--filter", default="demo-k8s-agent", help="only print findings mentioning this")
    args = p.parse_args()

    grants = list(WarrantGrantAdapter(base_url=args.warrant_url).iter_grants())
    print(f"fetched {len(grants)} grants from warrant")

    cgroup_to_subject = {}
    if args.ebpf_events:
        cgroup_to_subject = _cgroup_to_subject_from_ebpf_file(args.ebpf_events)
        print(f"built cgroup->subject map for {len(cgroup_to_subject)} cgroups from eBPF output")

    config = Config(
        agent_uid=0,
        k8s_audit_path=args.audit_log,
        ebpf_events_path=args.ebpf_events,
        k8s_cgroup_to_subject=cgroup_to_subject,
        warrant_grants=grants,
        findings_path=args.run_dir / "findings.jsonl",
        state_path=args.run_dir / "agentwatch_state.json",
        emit_canon_verdicts=False,
    )
    findings = run_once(config)
    matched = [f for f in findings if args.filter in f.summary]
    print(f"{len(findings)} total findings, {len(matched)} matching '{args.filter}':")
    for f in matched:
        print(" ", f.detector, "|", f.summary)


if __name__ == "__main__":
    main()
