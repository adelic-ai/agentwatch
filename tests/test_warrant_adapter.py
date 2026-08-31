import json
import unittest

from agentwatch.adapters.authorization import Decision, GrantEvent
from agentwatch.adapters.warrant import WarrantGrantAdapter, _row_to_grant

# Exact shape of a real warrant `/audit/log` row - confirmed against warrant/audit.py's full_log()
# and main.py's handler this session: `subject`/`resource`, not `subject_id`/`resource_id` (the
# HTTP response renames the model's own field names).
_ROWS = [
    {
        "id": "aud-1",
        "timestamp": "2026-08-30T12:00:00+00:00",
        "subject": "demo-agent",
        "principal": "user:rick",
        "action": "get",
        "resource": "configmaps:default/agent-config",
        "decision": "PERMIT",
        "policy": "AGENT-DELEGATION-01",
        "facts": ["configmaps:default/agent-config belongsTo namespace:default"],
        "reason": "Delegation covers scope.",
        "obligation_id": None,
    },
    {
        # Malformed row: missing "resource" entirely - must be skipped, not crash the adapter.
        "id": "aud-2",
        "timestamp": "2026-08-30T12:00:01+00:00",
        "subject": "demo-agent",
        "principal": "user:rick",
        "action": "create",
        "decision": "FORBID",
        "policy": "AGENT-DELEGATION-04",
        "facts": [],
        "reason": "Resource does not exist.",
        "obligation_id": None,
    },
]


def _fake_fetch(url: str) -> bytes:
    assert url.endswith("/audit/log")
    return json.dumps(_ROWS).encode("utf-8")


class WarrantGrantAdapterTest(unittest.TestCase):
    def test_iter_grants_maps_real_audit_log_row_shape(self) -> None:
        adapter = WarrantGrantAdapter(base_url="http://localhost:8000", fetch=_fake_fetch)
        grants = list(adapter.iter_grants())
        self.assertEqual(len(grants), 1)  # the malformed row is dropped, not raised
        g = grants[0]
        self.assertEqual(g.subject_id, "demo-agent")
        self.assertEqual(g.action, "get")
        self.assertEqual(g.resource_id, "configmaps:default/agent-config")
        self.assertEqual(g.decision, Decision.PERMIT)
        self.assertIsInstance(g.raw_ref, dict)

    def test_base_url_trailing_slash_does_not_double_up(self) -> None:
        seen = {}

        def fetch(url: str) -> bytes:
            seen["url"] = url
            return b"[]"

        WarrantGrantAdapter(base_url="http://localhost:8000/", fetch=fetch).iter_grants()
        self.assertEqual(seen["url"], "http://localhost:8000/audit/log")

    def test_non_json_response_yields_no_grants_not_a_crash(self) -> None:
        adapter = WarrantGrantAdapter(base_url="http://x", fetch=lambda url: b"not json")
        self.assertEqual(list(adapter.iter_grants()), [])

    def test_unrecognized_decision_string_is_skipped(self) -> None:
        row = dict(_ROWS[0])
        row["decision"] = "SOMETHING_NEW"
        adapter = WarrantGrantAdapter(
            base_url="http://x", fetch=lambda url: json.dumps([row]).encode()
        )
        self.assertEqual(list(adapter.iter_grants()), [])


class RowToGrantTest(unittest.TestCase):
    def test_missing_timestamp_is_skipped(self) -> None:
        row = dict(_ROWS[0])
        row["timestamp"] = "not a timestamp"
        self.assertIsNone(_row_to_grant(row))

    def test_valid_row_round_trips(self) -> None:
        g = _row_to_grant(_ROWS[0])
        self.assertIsInstance(g, GrantEvent)
        self.assertEqual(g.subject_id, "demo-agent")


if __name__ == "__main__":
    unittest.main()
