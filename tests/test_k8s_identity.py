import unittest

from agentwatch.events import EXEC, K8S_ACTION, GroundTruthEvent
from agentwatch.reconciler.k8s_identity import IdentityCorrelator, subject_from_k8s_username


class SubjectFromK8sUsernameTest(unittest.TestCase):
    def test_serviceaccount_username_extracts_name(self) -> None:
        self.assertEqual(
            subject_from_k8s_username("system:serviceaccount:default:demo-agent"), "demo-agent"
        )

    def test_non_serviceaccount_username_returns_none(self) -> None:
        self.assertIsNone(subject_from_k8s_username("system:node:worker-1"))
        self.assertIsNone(subject_from_k8s_username("rick@example.com"))

    def test_empty_or_none_returns_none(self) -> None:
        self.assertIsNone(subject_from_k8s_username(None))
        self.assertIsNone(subject_from_k8s_username(""))


class IdentityCorrelatorTest(unittest.TestCase):
    def test_k8s_action_event_resolves_via_username(self) -> None:
        correlator = IdentityCorrelator()
        ev = GroundTruthEvent(
            ts=1.0, kind=K8S_ACTION, comm="system:serviceaccount:default:demo-agent",
            args=("get", "configmaps:default/agent-config"),
        )
        self.assertEqual(correlator.subject_for(ev), "demo-agent")

    def test_ebpf_event_resolves_via_injected_cgroup_mapping(self) -> None:
        correlator = IdentityCorrelator(cgroup_to_subject={"cg-abc123": "demo-agent"})
        ev = GroundTruthEvent(ts=1.0, kind=EXEC, pid=42, cgroup="cg-abc123")
        self.assertEqual(correlator.subject_for(ev), "demo-agent")

    def test_ebpf_event_with_unmapped_cgroup_fails_correlation(self) -> None:
        correlator = IdentityCorrelator(cgroup_to_subject={"cg-abc123": "demo-agent"})
        ev = GroundTruthEvent(ts=1.0, kind=EXEC, pid=42, cgroup="cg-unknown")
        self.assertIsNone(correlator.subject_for(ev))

    def test_event_with_no_cgroup_and_no_username_fails_correlation(self) -> None:
        correlator = IdentityCorrelator()
        ev = GroundTruthEvent(ts=1.0, kind=EXEC, pid=42)
        self.assertIsNone(correlator.subject_for(ev))

    def test_k8s_action_with_unrecognized_username_fails_correlation(self) -> None:
        correlator = IdentityCorrelator()
        ev = GroundTruthEvent(ts=1.0, kind=K8S_ACTION, comm="system:node:worker-1")
        self.assertIsNone(correlator.subject_for(ev))

    def test_k8s_action_with_unrecognized_username_falls_back_to_cgroup(self) -> None:
        """A translated exec-as-action event (k8s_scope.exec_events_as_actions) has kind=K8S_ACTION
        but comm is a process name, never a ServiceAccount username - must fall through to the
        cgroup mapping rather than stop dead at the failed username match. Real K8s-audit events
        never carry a cgroup at all, so this fallback is inert for them (see subject_for's
        docstring) - this pins the new-behavior half specifically."""
        correlator = IdentityCorrelator(cgroup_to_subject={"c1": "demo-agent"})
        ev = GroundTruthEvent(ts=1.0, kind=K8S_ACTION, comm="cat", args=("exec", "process:cat"), cgroup="c1")
        self.assertEqual(correlator.subject_for(ev), "demo-agent")


if __name__ == "__main__":
    unittest.main()
