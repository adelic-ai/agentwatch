"""K8s API-server audit log (`audit.k8s.io/v1`, JSON Lines) -> normalized GroundTruthEvent stream.

K8S-DESIGN.md §1. Same adapter contract as `audit_log.py`/`journald.py`: `parse_lines(lines) ->
(events, stats)`, never raises on a bad line, an unrecognized shape is a recorded skip reason, not
a silent drop.

SCOPE, STATED HERE SO IT ISN'T OVERSOLD LATER (K8S-DESIGN.md §1): this parser reads a *local,
tailable* audit log file - what a self-managed control plane (or `kind`, the demo target) writes
via `--audit-log-path`. A managed control plane (EKS/GKE/AKS) delivers audit events through the
cloud provider's own logging service instead of a file - a different integration, not built here.

ONE EVENT PER REQUEST, NOT PER LINE
------------------------------------
The K8s audit backend can write the *same* request multiple times, once per stage
(`RequestReceived`, `ResponseStarted`, `ResponseComplete`) depending on the configured audit
policy's `level`. Only `ResponseComplete` carries the actual outcome (`responseStatus.code`) and is
the terminal, non-duplicate view of "this action happened, here is what came of it" - the other
stages are read (so a `stage`-less or unrecognized-stage line is still counted/skipped correctly)
but never turned into an event, or every completed action would be double- or triple-counted.

RESOURCE ID SHAPE - A REAL DEVIATION FROM K8S-DESIGN.md's ILLUSTRATIVE EXAMPLES
---------------------------------------------------------------------------------
K8S-DESIGN.md's examples use a singular resource kind (`"configmap:default/agent-config"`). The
real `objectRef.resource` field K8s actually emits is the API's plural resource name
(`"configmaps"`, `"secrets"`, `"pods"`) - there is no singular form anywhere in the audit record to
recover it from. This parser builds `resource_id` as `f"{objectRef.resource}:{namespace}/{name}"`
using exactly what K8s gives, i.e. `"configmaps:default/agent-config"`. Whoever wires the demo's
Warrant `Resource` registration (K8S-DESIGN.md §6) MUST register the plural form to match, or every
comparison in `reconciler/k8s_scope.py` silently fails to line up two strings that were never going
to be equal. Flagged here rather than silently reconciled, per this repo's convention of recording
a divergence instead of papering over it (see DECISIONS.md).

Cluster-scoped requests (no `objectRef.namespace`, e.g. a `Node` read) build
`resource_id` as `f"{resource}:{name}"` (no leading `/`), so a cluster-scoped and a
namespace-scoped id are never accidentally string-equal.

WHY THIS DOESN'T CARRY A PID/EXE THE WAY AN EXEC EVENT DOES
--------------------------------------------------------------
A K8s audit event has no process-tree shape - it's a control-plane API call, not a syscall. `pid`/
`ppid`/`uid` are left `None` (this is `events.K8S_ACTION`, not `EXEC` - orphan.py's ancestry walk
only ever looks at `EXEC`, so leaving these `None` cannot silently confuse process-tree scoping).
The caller identity K8s *does* give us - `user.username`, normally
`system:serviceaccount:<namespace>:<name>` for an agent's ServiceAccount - is carried in `comm` (so
it prints in the same place an EXEC event's comm would) and verbatim in `raw`; identity correlation
to a Warrant `subject_id` (K8S-DESIGN.md §3) reads it from there, not from a field this parser would
have to invent.
"""
from __future__ import annotations

import json
from typing import Iterable, Iterator

from agentwatch.events import K8S_ACTION, GroundTruthEvent, ParseStats

_TERMINAL_STAGE = "ResponseComplete"


def _parse_ts(raw: object) -> float | None:
    """RFC3339 (`2026-08-30T12:00:00.123456Z`) -> epoch seconds. `None` if unparseable/absent -
    never guessed, same reasoning as audit_log.py's `_parse_timestamp`: every downstream check is a
    time-window comparison, so an invented timestamp would produce confident nonsense."""
    if not isinstance(raw, str) or not raw:
        return None
    s = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        from datetime import datetime

        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return None


def _resource_id(object_ref: dict) -> str | None:
    resource = object_ref.get("resource")
    name = object_ref.get("name")
    if not resource or not name:
        return None
    namespace = object_ref.get("namespace")
    return f"{resource}:{namespace}/{name}" if namespace else f"{resource}:{name}"


def parse_lines(lines: Iterable[str]) -> tuple[list[GroundTruthEvent], ParseStats]:
    """Parse raw `audit.k8s.io/v1` JSON-lines into K8S_ACTION GroundTruthEvents. Never raises."""
    stats = ParseStats()
    events: list[GroundTruthEvent] = []
    for raw_line in lines:
        stats.lines_total += 1
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            stats.record_skip("json_decode_error")
            continue
        if not isinstance(obj, dict):
            stats.record_skip("not_a_json_object")
            continue

        if obj.get("kind") != "Event":
            stats.record_skip("not_an_audit_event")
            continue
        if obj.get("stage") != _TERMINAL_STAGE:
            # Not a skip: a RequestReceived/ResponseStarted line for a request whose
            # ResponseComplete line we will (or already did) see is expected, not unreadable input.
            continue

        object_ref = obj.get("objectRef")
        if not isinstance(object_ref, dict):
            stats.record_skip("no_object_ref")  # non-resource URL (e.g. /healthz) - not an action
            continue
        resource_id = _resource_id(object_ref)
        if resource_id is None:
            stats.record_skip("object_ref_incomplete")
            continue

        ts = _parse_ts(obj.get("requestReceivedTimestamp")) or _parse_ts(obj.get("stageTimestamp"))
        if ts is None:
            stats.record_skip("timestamp_unparseable")
            continue

        verb = obj.get("verb")
        username = (obj.get("user") or {}).get("username")
        response_status = obj.get("responseStatus") or {}
        code = response_status.get("code")

        try:
            event = GroundTruthEvent(
                ts=ts,
                kind=K8S_ACTION,
                comm=username,
                args=(verb, resource_id),
                success=(code is not None and code < 400) if code is not None else None,
                source="k8s_audit",
                raw=obj,
            )
        except Exception:
            stats.record_skip("record_build_error")
            continue
        stats.events_emitted += 1
        events.append(event)
    return events, stats
