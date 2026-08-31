"""`AuthorizationAdapter` reading Warrant's own `/audit/log` (K8S-DESIGN.md §2).

No new code in `warrant` - `/audit/log` (main.py:155) is already a generic, public endpoint
returning `warrant/audit.py`'s `full_log()` rows verbatim; nothing here needed Warrant to add a
K8s-specific route. Confirmed against the real handler this session: each row is
`{id, timestamp (ISO), subject, principal, action, resource, decision, policy, facts, reason,
obligation_id}` - `subject`/`resource`, not `subject_id`/`resource_id` (the HTTP response renames
the model's own field names), which is why `_row_to_grant` maps them explicitly rather than
splatting the dict into `GrantEvent`.

Uses `urllib.request` (stdlib), not `httpx` - agentwatch declares zero dependencies on principle
(pyproject.toml, BUILD_NOTES.md: "stdlib-only... arguably the right call for a security-monitoring
tool anyway"); it does not follow `warrant`'s own demo code in reaching for a third-party HTTP
client just because `warrant` did.

`fetch` is an injected callable (`str -> bytes`), same pattern as `groundtruth/ebpf_capture.py`'s
`elevation_prefix` and warden's `RealIncusClient`/`FakeIncusClient` split elsewhere in this stack:
the thing that talks to a real network is swappable data, not hardcoded inside the class, so tests
exercise the real parsing/mapping logic against a fixture response with no live `warrant` process
required. `RealFetch` (module-level, the actual `urlopen` call) is the production default.
"""
from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable, List, Optional

from agentwatch.adapters.authorization import Decision, GrantEvent

DEFAULT_TIMEOUT_SECONDS = 10.0


def real_fetch(url: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - operator-supplied URL
        return resp.read()


def _parse_ts(raw: object) -> Optional[float]:
    """`warrant.models.utcnow()` is always `datetime.now(timezone.utc)` at the source, but
    `/audit/log`'s JSON serialization drops the offset - the wire string looks naive
    (`"2026-08-31T02:04:52.784585"`, no `Z`/`+00:00`) even though it's always UTC. `.timestamp()`
    on a naive datetime assumes the *local* system timezone, not UTC - on any host not running in
    UTC this silently shifts every grant's epoch by the local offset. Confirmed for real against a
    live warrant instance on a UTC-4 host: a grant issued before a K8s action computed as issued
    ~4h *after* it, so `_grant_authorizes`'s `grant.ts <= at_ts` wrongly failed and a legitimately
    PERMIT-ed action was flagged CONFIRMED. Fix: a tz-naive parse result is UTC, not local -
    attach it explicitly rather than let `.timestamp()` guess."""
    if not isinstance(raw, str) or not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _row_to_grant(row: dict) -> Optional[GrantEvent]:
    """One `/audit/log` row -> `GrantEvent`, or `None` if the row is malformed - defensive the same
    way every other adapter in this codebase is (audit_log.py, journald.py, k8s_audit.py): a row
    this reads wrong must be skipped, never turned into a `GrantEvent` carrying invented data."""
    subject = row.get("subject")
    action = row.get("action")
    resource = row.get("resource")
    decision_raw = row.get("decision")
    ts = _parse_ts(row.get("timestamp"))
    if not subject or not action or not resource or ts is None:
        return None
    try:
        decision = Decision(decision_raw)
    except ValueError:
        return None
    return GrantEvent(
        subject_id=subject, action=action, resource_id=resource, decision=decision, ts=ts, raw_ref=row
    )


@dataclass
class WarrantGrantAdapter:
    """`AuthorizationAdapter` over a live (or fake, via `fetch`) Warrant instance's `/audit/log`."""

    base_url: str
    fetch: Callable[[str], bytes] = real_fetch

    def iter_grants(self) -> Iterable[GrantEvent]:
        url = self.base_url.rstrip("/") + "/audit/log"
        raw = self.fetch(url)
        try:
            rows = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if not isinstance(rows, list):
            return []
        grants: List[GrantEvent] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            grant = _row_to_grant(row)
            if grant is not None:
                grants.append(grant)
        return grants
