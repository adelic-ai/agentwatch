import unittest
from pathlib import Path

from agentwatch.events import K8S_ACTION
from agentwatch.groundtruth.k8s_audit import parse_lines

SAMPLE = Path(__file__).parent / "fixtures" / "k8s_audit" / "audit.jsonl"


class K8sAuditParserTest(unittest.TestCase):
    def test_sample_event_count_and_terminal_stage_only(self) -> None:
        with SAMPLE.open() as fh:
            events, stats = parse_lines(fh)
        # 6 lines: RequestReceived (not terminal, not a skip) + 3 ResponseComplete + a
        # non-resource-URL ResponseComplete (skipped) + invalid JSON (skipped).
        self.assertEqual(stats.lines_total, 6)
        self.assertEqual(len(events), 3)
        self.assertTrue(all(e.kind == K8S_ACTION for e in events))
        self.assertEqual(stats.skip_reasons.get("no_object_ref"), 1)
        self.assertEqual(stats.skip_reasons.get("json_decode_error"), 1)

    def test_resource_id_shape_is_plural_kubernetes_form(self) -> None:
        with SAMPLE.open() as fh:
            events, _ = parse_lines(fh)
        get_event = next(e for e in events if e.args[0] == "get")
        self.assertEqual(get_event.args, ("get", "configmaps:default/agent-config"))

    def test_success_derived_from_response_status_code(self) -> None:
        with SAMPLE.open() as fh:
            events, _ = parse_lines(fh)
        create_secret = next(e for e in events if e.args[1] == "secrets:default/leaked-secret")
        self.assertFalse(create_secret.success)
        get_configmap = next(e for e in events if e.args[1] == "configmaps:default/agent-config")
        self.assertTrue(get_configmap.success)

    def test_username_carried_in_comm(self) -> None:
        with SAMPLE.open() as fh:
            events, _ = parse_lines(fh)
        self.assertTrue(
            all(e.comm == "system:serviceaccount:default:demo-agent" for e in events)
        )

    def test_no_pid_ancestry_fields(self) -> None:
        """A K8s action is not a process - orphan.py's ancestry walk must never mistake one for a
        candidate EXEC (it filters ev.kind != EXEC, but this pins the invariant it relies on)."""
        with SAMPLE.open() as fh:
            events, _ = parse_lines(fh)
        self.assertTrue(all(e.pid is None and e.ppid is None for e in events))

    def test_only_response_complete_stage_emits(self) -> None:
        # The RequestReceived line for auditID a1 shares every field with its ResponseComplete
        # sibling except stage - if the parser emitted both, this would be 4 events, not 3.
        with SAMPLE.open() as fh:
            events, _ = parse_lines(fh)
        self.assertEqual(len(events), 3)

    def test_malformed_lines_never_raise(self) -> None:
        parse_lines(["not json", "{}", '{"kind": "Event"}', ""])  # must not raise

    def test_cluster_scoped_resource_id_has_no_namespace_slash(self) -> None:
        line = (
            '{"kind":"Event","apiVersion":"audit.k8s.io/v1","stage":"ResponseComplete",'
            '"verb":"get","user":{"username":"system:serviceaccount:default:demo-agent"},'
            '"objectRef":{"resource":"nodes","name":"node-1","apiVersion":"v1"},'
            '"responseStatus":{"code":200},'
            '"requestReceivedTimestamp":"2026-08-30T12:00:00.000000Z"}'
        )
        events, _ = parse_lines([line])
        self.assertEqual(events[0].args, ("get", "nodes:node-1"))


if __name__ == "__main__":
    unittest.main()
