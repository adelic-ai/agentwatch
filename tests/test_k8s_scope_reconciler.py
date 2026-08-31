"""reconciler/k8s_scope.py - including the negative-test suite K8S-DESIGN.md §6/§8 calls out as
required, not optional: a demo that only shows one violation proves recall on one case, not
correctness (Siphonophore-style - verify no false positive on legitimately-granted actions, and
that fabricated/expanded scope is still caught, not just an unauthorized action from nothing)."""
import unittest

from agentwatch.adapters.authorization import Decision, GrantEvent
from agentwatch.events import CLONE, EXEC, K8S_ACTION, GroundTruthEvent
from agentwatch.reconciler.k8s_identity import IdentityCorrelator
from agentwatch.reconciler.k8s_scope import exec_events_as_actions, reconcile_k8s_scope
from agentwatch.reconciler.verdict import Verdict

SUBJECT = "demo-agent"
USERNAME = f"system:serviceaccount:default:{SUBJECT}"


def _k8s_event(ts: float, verb: str, resource_id: str, username: str = USERNAME) -> GroundTruthEvent:
    return GroundTruthEvent(ts=ts, kind=K8S_ACTION, comm=username, args=(verb, resource_id), success=True)


def _grant(ts: float, action: str, resource_id: str, decision: Decision = Decision.PERMIT,
           subject_id: str = SUBJECT) -> GrantEvent:
    return GrantEvent(subject_id=subject_id, action=action, resource_id=resource_id, decision=decision, ts=ts)


class HappyPathTest(unittest.TestCase):
    """K8S-DESIGN.md §6 step 4: the authorized action produces no finding."""

    def test_authorized_action_produces_no_confirmed_or_gap(self) -> None:
        grants = [_grant(0.0, "get", "configmaps:default/agent-config")]
        events = [_k8s_event(5.0, "get", "configmaps:default/agent-config")]
        results = reconcile_k8s_scope(events, grants, IdentityCorrelator())
        self.assertEqual(results, [])  # matched - nothing to report, same as orphan.py's matched case


class ScriptedViolationTest(unittest.TestCase):
    """K8S-DESIGN.md §6 step 5/7: the unauthorized action produces CONFIRMED."""

    def test_action_with_no_grant_at_all_is_confirmed(self) -> None:
        grants = [_grant(0.0, "get", "configmaps:default/agent-config")]
        events = [
            _k8s_event(5.0, "get", "configmaps:default/agent-config"),  # authorized, no finding
            _k8s_event(6.0, "create", "secrets:default/leaked-secret"),  # never granted
        ]
        results = reconcile_k8s_scope(events, grants, IdentityCorrelator())
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].verdict, Verdict.CONFIRMED)
        self.assertEqual(results[0].event.args, ("create", "secrets:default/leaked-secret"))

    def test_explicit_forbid_grant_is_confirmed_with_forbid_reason(self) -> None:
        grants = [_grant(0.0, "delete", "pods:default/other-pod", decision=Decision.FORBID)]
        events = [_k8s_event(5.0, "delete", "pods:default/other-pod")]
        results = reconcile_k8s_scope(events, grants, IdentityCorrelator())
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].verdict, Verdict.CONFIRMED)
        self.assertIn("FORBID", results[0].reason)


class NegativeTestSuite(unittest.TestCase):
    """Required by K8S-DESIGN.md §6/§8, not optional. Every case here must NOT be a false
    positive, or must correctly catch a fabricated/expanded-scope attempt - never the reverse."""

    def test_no_false_positive_on_legitimately_granted_action(self) -> None:
        grants = [
            _grant(0.0, "get", "configmaps:default/agent-config"),
            _grant(0.0, "list", "configmaps:default/agent-config"),
        ]
        events = [
            _k8s_event(5.0, "get", "configmaps:default/agent-config"),
            _k8s_event(6.0, "list", "configmaps:default/agent-config"),
        ]
        confirmed = [r for r in reconcile_k8s_scope(events, grants, IdentityCorrelator())
                     if r.verdict == Verdict.CONFIRMED]
        self.assertEqual(confirmed, [])

    def test_grant_for_a_different_resource_does_not_authorize_this_one(self) -> None:
        """Fabricated/expanded scope: the agent has a real PERMIT, just not for THIS resource -
        it must not leak authorization across resources it merely resembles. (The unexercised
        grant for the OTHER resource correctly also surfaces as its own GAP candidate - not
        asserted on here, that's GapTest's job; this test isolates the CONFIRMED claim only.)"""
        grants = [_grant(0.0, "get", "configmaps:default/agent-config")]
        events = [_k8s_event(5.0, "get", "configmaps:default/other-config")]
        confirmed = [r for r in reconcile_k8s_scope(events, grants, IdentityCorrelator())
                     if r.verdict == Verdict.CONFIRMED]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0].event.args[1], "configmaps:default/other-config")

    def test_grant_for_a_different_verb_does_not_authorize_this_one(self) -> None:
        """Read access does not imply write access - a `get` PERMIT must not authorize `delete`."""
        grants = [_grant(0.0, "get", "secrets:default/agent-config")]
        events = [_k8s_event(5.0, "delete", "secrets:default/agent-config")]
        confirmed = [r for r in reconcile_k8s_scope(events, grants, IdentityCorrelator())
                     if r.verdict == Verdict.CONFIRMED]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0].event.args[0], "delete")

    def test_grant_for_a_different_subject_does_not_authorize_this_agent(self) -> None:
        """Another agent's PERMIT must never authorize this one's action, even for the identical
        resource+verb - scope is per-identity, not per-resource."""
        grants = [_grant(0.0, "get", "configmaps:default/agent-config", subject_id="other-agent")]
        events = [_k8s_event(5.0, "get", "configmaps:default/agent-config")]
        confirmed = [r for r in reconcile_k8s_scope(events, grants, IdentityCorrelator())
                     if r.verdict == Verdict.CONFIRMED]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0].subject_id, SUBJECT)

    def test_grant_issued_after_the_action_does_not_retroactively_authorize_it(self) -> None:
        grants = [_grant(10.0, "get", "configmaps:default/agent-config")]  # granted AFTER
        events = [_k8s_event(5.0, "get", "configmaps:default/agent-config")]
        results = reconcile_k8s_scope(events, grants, IdentityCorrelator())
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].verdict, Verdict.CONFIRMED)


class GapTest(unittest.TestCase):
    def test_permit_with_no_entailed_action_is_gap(self) -> None:
        grants = [_grant(0.0, "get", "configmaps:default/agent-config")]
        results = reconcile_k8s_scope([], grants, IdentityCorrelator())
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].verdict, Verdict.GAP)
        self.assertEqual(results[0].grant, grants[0])

    def test_forbid_grant_never_produces_gap(self) -> None:
        grants = [_grant(0.0, "delete", "pods:default/x", decision=Decision.FORBID)]
        results = reconcile_k8s_scope([], grants, IdentityCorrelator())
        self.assertEqual(results, [])


class UnevaluableTest(unittest.TestCase):
    def test_unrecognized_identity_is_unevaluable_not_confirmed(self) -> None:
        """A correlation failure must never masquerade as either a clean run or a violation - see
        events.py K8S_ACTION and reconciler/k8s_identity.py's module docstring. (The grant itself,
        never having been matched to any resolved subject, correctly also surfaces as its own GAP
        candidate - GapTest's concern, not this test's.)"""
        grants = [_grant(0.0, "get", "configmaps:default/agent-config")]
        events = [_k8s_event(5.0, "get", "configmaps:default/agent-config", username="system:node:worker-1")]
        results = reconcile_k8s_scope(events, grants, IdentityCorrelator())
        unevaluable = [r for r in results if r.verdict == Verdict.UNEVALUABLE]
        confirmed = [r for r in results if r.verdict == Verdict.CONFIRMED]
        self.assertEqual(len(unevaluable), 1)
        self.assertEqual(confirmed, [])


class ExecEventsAsActionsTest(unittest.TestCase):
    """`exec_events_as_actions` - the translation that lets raw eBPF exec ground truth reuse this
    reconciler's already-tested matching logic instead of a parallel one (module docstring)."""

    def test_exec_event_becomes_process_scoped_k8s_action(self) -> None:
        ev = GroundTruthEvent(ts=1.0, kind=EXEC, comm="cat", cgroup="123")
        [translated] = exec_events_as_actions([ev])
        self.assertEqual(translated.kind, K8S_ACTION)
        self.assertEqual(translated.args, ("exec", "process:cat"))
        self.assertEqual(translated.cgroup, "123")  # identity correlation input preserved
        self.assertEqual(translated.ts, 1.0)

    def test_clone_events_are_excluded(self) -> None:
        """A fork alone runs no new binary - nothing to check against a process:<name> grant."""
        events = [GroundTruthEvent(ts=1.0, kind=CLONE, comm="bash")]
        self.assertEqual(exec_events_as_actions(events), [])

    def test_exec_with_no_comm_is_skipped_not_defaulted(self) -> None:
        events = [GroundTruthEvent(ts=1.0, kind=EXEC, comm=None)]
        self.assertEqual(exec_events_as_actions(events), [])

    def test_translated_exec_reconciles_through_the_same_path_as_a_k8s_action(self) -> None:
        """End-to-end: an eBPF-observed exec, once translated, is checked exactly like any K8s
        API action - authorized exec produces nothing, unauthorized exec is CONFIRMED."""
        grants = [_grant(0.0, "exec", "process:kubectl")]
        exec_events = [
            GroundTruthEvent(ts=5.0, kind=EXEC, comm="kubectl", cgroup="c1"),  # authorized
            GroundTruthEvent(ts=6.0, kind=EXEC, comm="cat", cgroup="c1"),  # never granted
        ]
        translated = exec_events_as_actions(exec_events)
        # identity correlation for these synthetic events comes from cgroup, not username -
        # comm was overwritten by the translation, so correlate via cgroup_to_subject.
        correlator = IdentityCorrelator(cgroup_to_subject={"c1": SUBJECT})
        results = reconcile_k8s_scope(translated, grants, correlator)
        confirmed = [r for r in results if r.verdict == Verdict.CONFIRMED]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0].event.args, ("exec", "process:cat"))


if __name__ == "__main__":
    unittest.main()
