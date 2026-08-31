"""Identity correlation across three separate namespaces (K8S-DESIGN.md §3) - the genuinely new
piece this build adds, not a wrapper around something that already existed.

Three things need joining on "this is the same agent," and nothing before this module did it:
  - K8s audit: `user.username`, normally `system:serviceaccount:<namespace>:<name>`
  - eBPF: `cgroup_id` (GroundTruthEvent.cgroup)
  - Warrant: `subject_id` (GrantEvent.subject_id, an `Identity.id`)

DEMO BINDING (K8S-DESIGN.md §3): the K8s ServiceAccount's *name* IS the Warrant `subject_id`,
provisioned identically on purpose - not inferred, not looked up against a second source of truth.
Get this wrong and detection silently misattributes: a K8s action from one agent's ServiceAccount
matched against a different agent's grant is a false negative dressed as authorization, not a
crash - which is exactly why this correlation step is its own module with its own tests, not three
lines inlined into a detector.

`cgroup_to_subject` is injected data, not looked up internally - same pattern as
`ebpf_capture.py`'s `elevation_prefix` and `adapters/warrant.py`'s `fetch`: the thing that actually
knows the live pod-to-ServiceAccount binding (the eBPF DaemonSet, reading K8s pod metadata off
`/sys/fs/cgroup` at capture time, per K8S-DESIGN.md §4) is not this module's job to rebuild.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Mapping, Optional

from agentwatch.events import K8S_ACTION, GroundTruthEvent

# `system:serviceaccount:<namespace>:<name>` - the standard K8s ServiceAccount username shape
# (see https://kubernetes.io/docs/reference/access-authn-authz/authentication/, unauthenticated
# here rather than fetched: this parser has no cluster to ask, only the string K8s already logged).
_SERVICEACCOUNT_USERNAME_RE = re.compile(r"^system:serviceaccount:(?P<namespace>[^:]+):(?P<name>[^:]+)$")


def subject_from_k8s_username(username: Optional[str]) -> Optional[str]:
    """`system:serviceaccount:default:demo-agent` -> `demo-agent` (the demo binding: SA name IS
    the Warrant subject_id). `None` for anything that isn't a ServiceAccount username at all
    (a human user, a node identity, garbage) - never guessed, an unmatched action from a non-SA
    identity is out of scope for this detector, not a correlation failure to report."""
    if not username:
        return None
    m = _SERVICEACCOUNT_USERNAME_RE.match(username)
    return m.group("name") if m else None


@dataclass
class IdentityCorrelator:
    """Resolves a `GroundTruthEvent` to the Warrant `subject_id` it should be checked against, or
    `None` if it can't be - callers (`reconciler/k8s_scope.py`) treat `None` as UNEVALUABLE, never
    as "no subject" (silently dropping it would be exactly the coverage hole
    `unevaluable_candidates` in orphan.py already exists to make visible instead of hiding)."""

    #: cgroup_id -> subject_id, built by the eBPF DaemonSet at capture time (not this module's
    #: job - see module docstring). Empty by default so a caller with only K8s-audit events (no
    #: eBPF wired yet) doesn't need to supply one.
    cgroup_to_subject: Mapping[str, str] = field(default_factory=dict)

    def subject_for(self, event: GroundTruthEvent) -> Optional[str]:
        """Username-shape first, cgroup fallback - not an either/or on `event.kind` alone.
        `k8s_scope.exec_events_as_actions` translates raw eBPF exec events into `K8S_ACTION`-kind
        copies (K8S-DESIGN.md's process-scoped grant reuse - see that module's docstring) so they
        reuse this reconciler's matching path; their `comm` is a process name, never a
        ServiceAccount username, so the regex correctly fails and this must fall through to
        `cgroup` rather than stopping at `kind == K8S_ACTION` and returning `None`. Safe for every
        real K8s-audit event too: those never carry a `cgroup` (k8s_audit.py never sets one), so
        a real event either matches the username regex or falls through to a no-op cgroup lookup -
        identical final result to before this fallback existed."""
        if event.kind == K8S_ACTION:
            subject = subject_from_k8s_username(event.comm)
            if subject is not None:
                return subject
        if event.cgroup is not None:
            return self.cgroup_to_subject.get(event.cgroup)
        return None
