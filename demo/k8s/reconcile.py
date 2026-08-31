"""Reconcile real K8s ground truth against real Warrant grants (K8S-DESIGN.md §6/§8).

Validated for real, 2026-08-30/31, against a live `kind` cluster + in-cluster warrant on pop-os:
the authorized ConfigMap read produces no finding; the unauthorized Secret-create produces
`CONFIRMED` (technique `k8s_scope_violation`). Along the way this run caught a real bug (fixed,
see agentwatch/adapters/warrant.py's docstring and git history) that all 37 unit tests from the
original build missed, because their fixtures never used warrant's actual offset-less wire
timestamp shape - a live run is not optional, unit tests alone did not prove this worked.

Usage, after `kind-config.yaml` + `warrant-deploy.yaml` + `demo-agent-rbac.yaml` +
`demo-agent-pod.yaml` are applied and the demo agent has run (see this directory's README):

    kubectl port-forward svc/warrant 18000:8000 &
    python3 reconcile.py [--audit-log PATH] [--warrant-url URL] [--filter SUBSTRING]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agentwatch.adapters.warrant import WarrantGrantAdapter
from agentwatch.run import Config, run_once


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--audit-log", type=Path, default=Path.home() / "k8s-audit/logs/audit.log")
    p.add_argument("--warrant-url", default="http://127.0.0.1:18000")
    p.add_argument("--run-dir", type=Path, default=Path.home() / "k8s-audit")
    p.add_argument("--filter", default="demo-k8s-agent", help="only print findings mentioning this")
    args = p.parse_args()

    grants = list(WarrantGrantAdapter(base_url=args.warrant_url).iter_grants())
    print(f"fetched {len(grants)} grants from warrant")

    config = Config(
        agent_uid=0,
        k8s_audit_path=args.audit_log,
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
