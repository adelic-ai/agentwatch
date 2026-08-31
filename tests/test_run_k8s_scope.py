"""run.py wiring for the K8s scope-violation detector (K8S-DESIGN.md §0) - Config's new fields are
additive, `None` = not collected/contributes nothing, same contract as every other optional plane.
"""
import tempfile
import unittest
from pathlib import Path

from agentwatch.adapters.authorization import Decision, GrantEvent
from agentwatch.run import Config, run_once

FIXTURES = Path(__file__).parent / "fixtures" / "k8s_audit" / "audit.jsonl"
EBPF_FIXTURES = Path(__file__).parent / "fixtures" / "ebpf" / "events.jsonl"
AGENT_UID = 3000


class RunOnceK8sScopeTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _config(self, **overrides) -> Config:
        base = dict(
            agent_uid=AGENT_UID,
            findings_path=self.tmp / "findings.jsonl",
            state_path=self.tmp / "state.json",
        )
        base.update(overrides)
        return Config(**base)

    def test_absent_k8s_config_contributes_nothing(self) -> None:
        """Regression guard: adding this detector must not change output for any caller that
        doesn't wire it - the fixture's audit.log/journal.log/transcripts are all absent here too,
        so this exercises the pure "nothing configured" baseline."""
        findings = run_once(self._config(), now=1700000000.0)
        self.assertEqual(findings, [])

    def test_k8s_audit_path_without_grants_contributes_nothing(self) -> None:
        """warrant_grants=None (unset) must suppress the detector even though real K8s ground
        truth exists on disk - a channel wired on only one side must not half-run."""
        findings = run_once(
            self._config(k8s_audit_path=FIXTURES), now=1700000000.0
        )
        self.assertEqual([f for f in findings if "k8s" in f.detector], [])

    def test_wired_end_to_end_flags_the_unauthorized_secret_create(self) -> None:
        grants = [
            GrantEvent(
                subject_id="demo-agent", action="get", resource_id="configmaps:default/agent-config",
                decision=Decision.PERMIT, ts=0.0,
            )
        ]
        findings = run_once(
            self._config(k8s_audit_path=FIXTURES, warrant_grants=grants), now=1700000000.0
        )
        # Fixture has two ungranted actions: the secret create AND the pod exec (both under
        # `demo-agent`'s only grant, which covers neither) - both must be flagged, not just one.
        k8s_findings = [f for f in findings if f.detector == "k8s_scope_violation"]
        self.assertEqual(len(k8s_findings), 2)
        flagged_resources = {f.evidence["resource_id"] for f in k8s_findings}
        self.assertEqual(flagged_resources, {"secrets:default/leaked-secret", "pods:default/other-pod"})
        self.assertTrue(all(f.evidence["verdict"] == "CONFIRMED" for f in k8s_findings))
        self.assertTrue(all(f.plane_trust is None for f in k8s_findings))  # undeclared by default, honest

    def test_ebpf_only_flags_the_unauthorized_process_exec(self) -> None:
        """demo/k8s/ebpf/capture_loop.py's JSONL, real fixture shape (subject_id/node included -
        the loader must drop them, see _load_ebpf_events' docstring). kubectl is granted, cat is
        not - via exec_events_as_actions's process:<name> reframing, not a second detector."""
        grants = [
            GrantEvent(
                subject_id="demo-agent", action="exec", resource_id="process:kubectl",
                decision=Decision.PERMIT, ts=0.0,
            )
        ]
        findings = run_once(
            self._config(
                ebpf_events_path=EBPF_FIXTURES,
                warrant_grants=grants,
                k8s_cgroup_to_subject={"c1": "demo-agent"},
            ),
            now=1700000000.0,
        )
        k8s_findings = [f for f in findings if f.detector == "k8s_scope_violation"]
        self.assertEqual(len(k8s_findings), 1)
        self.assertEqual(k8s_findings[0].evidence["resource_id"], "process:cat")

    def test_k8s_audit_and_ebpf_combine_in_one_reconciliation_pass(self) -> None:
        """Both ground-truth shapes at once - the K8s-audit violation and the eBPF-exec violation
        both surface, from the same run_once call, same findings.jsonl."""
        grants = [
            GrantEvent(
                subject_id="demo-agent", action="get", resource_id="configmaps:default/agent-config",
                decision=Decision.PERMIT, ts=0.0,
            ),
            GrantEvent(
                subject_id="demo-agent", action="exec", resource_id="process:kubectl",
                decision=Decision.PERMIT, ts=0.0,
            ),
        ]
        findings = run_once(
            self._config(
                k8s_audit_path=FIXTURES,
                ebpf_events_path=EBPF_FIXTURES,
                warrant_grants=grants,
                k8s_cgroup_to_subject={"c1": "demo-agent"},
            ),
            now=1700000000.0,
        )
        k8s_findings = [f for f in findings if f.detector == "k8s_scope_violation"]
        flagged = {f.evidence["resource_id"] for f in k8s_findings}
        self.assertIn("process:cat", flagged)  # from eBPF
        self.assertIn("secrets:default/leaked-secret", flagged)  # from K8s audit

    def test_rerun_dedups_the_same_finding(self) -> None:
        grants = [
            GrantEvent(
                subject_id="demo-agent", action="get", resource_id="configmaps:default/agent-config",
                decision=Decision.PERMIT, ts=0.0,
            )
        ]
        config = self._config(k8s_audit_path=FIXTURES, warrant_grants=grants)
        first = run_once(config, now=1700000000.0)
        second = run_once(config, now=1700000001.0)
        self.assertTrue(any(f.detector == "k8s_scope_violation" for f in first))
        self.assertEqual([f for f in second if f.detector == "k8s_scope_violation"], [])


if __name__ == "__main__":
    unittest.main()
