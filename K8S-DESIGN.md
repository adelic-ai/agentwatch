# AgentWatch on Kubernetes — design doc and build plan

**Status:** draft, 2026-08-30. Extends the reference implementation described in `CONTRACT.md`
with a Kubernetes ground-truth plane and a new authorization plane. Rationale and rejected
alternatives that don't need to survive in a build plan live in `considerations/k8s-extension.md`
(gitignored, not part of this doc's audience).

**One line:** reconcile what an agent actually did on Kubernetes (K8s audit log + eBPF) against
what `warrant` actually granted it — the same don't-trust-self-report thesis `CONTRACT.md` already
formalizes, extended with a second, independently-issued reference plane.

## 0. Fit against the existing contract — the one real architectural decision

`CONTRACT.md` defines exactly two planes: **Plane A** (`TranscriptAdapter`, self-report, LOW
trust — parses per-runtime *raw text*) and **Plane B** (`GroundTruthAdapter`, OS telemetry, trust
tier declared by substrate). A Warrant grant is neither. It isn't the agent's self-report (it's an
independent policy engine's own decision), and it isn't raw text needing a runtime-specific parser
(Warrant's `audit.py.full_log()` already returns structured rows). Forcing it through
`TranscriptAdapter.parse_lines(lines: Iterable[str])` would work mechanically but would silently
misrepresent a HIGH-trust independent authorization as a LOW-trust self-report in the one place
(`CONTRACT.md`) meant to be normative about exactly that distinction.

**Decision: add a third role, not stretch an existing one.**

```python
# agentwatch/adapters/authorization.py (new)
class AuthorizationAdapter(Protocol):
    def iter_grants(self) -> Iterable[GrantEvent]: ...

# GrantEvent (normative fields, modeled directly on warrant/models.py's AuditRecord)
#   subject_id: str        # the agent identity, matches Identity.id in warrant
#   action: str
#   resource_id: str       # e.g. "configmap:default/agent-config"
#   decision: Decision     # PERMIT | REQUIRE_APPROVAL | FORBID (warrant.models.Decision)
#   ts: float
#   raw_ref: Any
```

This is additive to `Config` (`run.py`), same pattern as `ground_truth_events`/`audit_log_path`
today — a new optional field, `None` meaning "not collected, contributes nothing," never a breaking
change to existing conformant callers. New detector technique `AGENT.k8s-scope-violation`, reusing
the existing NORMATIVE `Verdict` vocabulary rather than inventing a parallel one:

| Verdict | Meaning for this detector |
|---|---|
| `CONFIRMED` | K8s/eBPF ground truth shows an action with no matching `GrantEvent` (or a matching `FORBID`), on a channel that **is** collected. |
| `GAP` | A `PERMIT` grant exists but its entailed K8s action never shows up in ground truth, while that channel **is** collected. |
| `NONE` | The authorization channel itself wasn't collected for this session — silence proves nothing. |
| `UNEVALUABLE` | Identity correlation (§3) couldn't map the ground-truth event to a `subject_id` at all. |

## 1. Ground-truth plane: `groundtruth/k8s_audit.py`

Same contract as existing `audit_log.py`/`journald.py` — external source → `GroundTruthEvent`,
polled at the existing `--watch --interval` cadence (CLI's poll-not-stream design, §7 non-goal, is
unchanged and not something this needs to fix).

**Explicit scope limit, stated up front so it can't be silently oversold later:** this adapter
targets a **self-managed control plane with a local, readable audit log file** — which is what
`kind` (the demo target, §6) provides. A managed control plane (EKS/GKE/AKS) delivers audit events
through the cloud provider's own logging service (CloudWatch/Cloud Logging/Azure Monitor) instead
of a tailable file — a materially different integration, explicitly **out of scope for this build**.
Do not describe this adapter as "K8s audit log support" without that qualifier.

eBPF capture needs no new code — `groundtruth/ebpf.py`/`ebpf_capture.py` already tag events with
`cgroup_id` and the reconciler already does cgroup-keyed scoping (`runtime_scope.py`). What's new
is packaging (§5), not capture logic.

## 2. Authorization plane: `adapters/warrant.py`

Implements `AuthorizationAdapter`. Reads Warrant's existing audit trail (`warrant/audit.py`'s
`full_log`) — **no new code needed in `warrant`**. Maps each relevant `AuditRecord` row to a
`GrantEvent`.

**Warrant's role is decision oracle only — never an inline K8s gateway.** Do not build a
`warrant/gateway.py` route that proxies real K8s API calls through Warrant (the way
`/gateway/documents/{id}` does for documents today). That would make Warrant the trusted
enforcement point with nothing independent left to check it against — the same self-report problem
this whole system exists to catch. The agent requests authorization, Warrant logs the decision, the
agent then acts against the real K8s API directly and independently, and this adapter reconciles
the two after the fact. The separation is load-bearing, not a shortcut.

Warrant's `Resource`/`Delegation` model needs no schema changes — already generic (`id`, `kind`,
`belongs_to`, not document-specific). Demo registers e.g. `id="configmap:default/agent-config"`,
`kind="k8s.configmap"`, `belongs_to="namespace:default"`.

## 3. Identity correlation — the genuinely new, hardest piece

Three identity namespaces need joining on "this is the same agent," and nothing today does this:
- eBPF: `cgroup_id`
- K8s audit: pod name / ServiceAccount
- Warrant: `subject_id` (an `Identity.id`, SPIFFE-shaped)

New module, `agentwatch/reconciler/k8s_identity.py`. Simplest correct binding for the demo: the
K8s pod's ServiceAccount name *is* the Warrant `subject_id` (provision the demo agent's K8s
ServiceAccount and Warrant Identity with the same name deliberately, don't infer a mapping).
`cgroup_id` → pod is resolved by the eBPF DaemonSet at capture time (it already runs on the node
and can read `/sys/fs/cgroup` pod metadata / the container runtime's own pod-UID-in-cgroup-path
convention). Get this binding wrong and detection silently misattributes — this is where a bug
produces a false negative or false positive, not the adapters.

## 4. Deployment topology

Two-tier — not a preference, forced by where eBPF can attach (it hooks a kernel; containers share
a node's kernel, a VM has its own):

- **`ebpf-capture` DaemonSet, one pod per node.** Wraps existing `ebpf.py` bpftrace program, no
  change to the program itself. Ships events to the central reconciler (§5 decides transport for
  the demo).
- **Reconciler — single centralized `Deployment` (one replica for the demo).** Its two reference
  inputs (K8s audit log, Warrant grant log) are already cluster-scoped, not node-scoped. Consumes
  eBPF events shipped from the DaemonSets the same way `run.py` already "fuses a pre-captured
  stream with the file planes" today — no new fusion concept, just a new source for it.

**State model — explicit demo-scope decision, not a silent gap.** `state.py` is a single flat JSON
file, no per-agent keying. For the demo (one agent), leave it unmodified — do not build
multi-tenant state keying, it's real work with no demo payoff. State this as an explicit
out-of-scope item in any writeup, not an oversight discovered later.

## 5. Response layer — deliberately outside AgentWatch

Not built in this repo. A separate consumer subscribes to `Finding`s and does containment:
isolate (NetworkPolicy / remove from Service endpoints) → capture forensic state → destroy/recreate.
AgentWatch stays pure detection — it never holds delete credentials on cluster resources. Stretch
goal, not required for the core deliverable (§8 definition of done doesn't require it).

## 6. Demo cluster and scripted scenario

Single-node `kind` cluster (sidesteps the managed-control-plane gap in §1 — `kind`'s control plane
is a local container, files readable directly). Sibling checkout discovery follows the existing
`WARDEN_AGENTWATCH_PATH`-style convention already used elsewhere in this stack.

Warrant runs in-cluster for the demo (`Deployment` + `ClusterIP Service`, built from its existing
`Dockerfile`) — a demo-convenience choice, not the recommended production topology. In production,
Warrant should run as genuinely external infrastructure.

1. Register `configmap:default/agent-config` (`kind="k8s.configmap"`) in Warrant; issue a
   Delegation scoped to `namespace:default`, `permitted_actions="read"`.
2. Provision the demo agent's K8s ServiceAccount with the same identifying name as its Warrant
   `subject_id` (§3).
3. Agent requests and receives a `PERMIT` from Warrant for `read configmap:default/agent-config`;
   logged via Warrant's existing audit trail — no new Warrant code.
4. Agent performs the real, authorized K8s read directly against the K8s API.
5. **Scripted violation:** agent then attempts an unauthorized action never granted — read
   `configmap:default/other-config`, or create a Secret, or exec into a sibling pod.
6. K8s audit log + eBPF (Plane B) capture both actions independently. Reconciler cross-references
   against Warrant's grant log (§2) via the identity binding (§3).
7. Expected: step 4 → no finding (matched grant). Step 5 → `CONFIRMED`, technique
   `AGENT.k8s-scope-violation`.

**Negative-test suite, Siphonophore-style — required, not optional:** verify the reconciler flags
fabricated/expanded scope and does NOT false-positive on legitimately-granted actions. A demo that
only shows the happy path plus one scripted violation proves recall on one case, not correctness —
mirrors why Siphonophore's negative enforcement tests exist.

## 7. Explicit non-goals (this build)

- Managed-control-plane (EKS/GKE/AKS) audit log delivery — §1.
- Multi-tenant state store — §4.
- Egress-compliance detector (comparing eBPF `connect()` against NetworkPolicy + Warrant scope) —
  designed in `considerations/k8s-extension.md`, real and additive later, not required for this
  deliverable.
- Real-time blocking/enforcement of any kind — detection only, everywhere in this system.
- A Warrant→K8s gateway route — actively rejected, §2, not just deferred.

## 8. Definition of done

Not resume-ready, not "the design is solid" — specifically: a real `kind` cluster, real Warrant
process, real eBPF DaemonSet, real K8s audit log, steps 1–7 above actually run end to end with a
`CONFIRMED` finding produced for the scripted violation and no finding for the authorized action,
plus the negative-test suite passing. Design work alone does not clear this bar — see
`considerations/k8s-extension.md`'s closing note on why an unbuilt capability doesn't belong in a
resume bullet.

## 9. Build order

1. `groundtruth/k8s_audit.py` against a `kind` cluster with audit logging enabled (audit policy +
   `--audit-log-path`, kind's kubeadm config patches) — unit tests against a captured fixture log,
   same shape as `audit_log.py`'s existing dialect-handling tests.
2. `adapters/authorization.py` (protocol) + `adapters/warrant.py` (impl) against a real running
   `warrant` instance — no new `warrant` code, integration test only.
3. `reconciler/k8s_identity.py` — the correlation layer, unit-tested against synthetic
   cgroup/pod/subject triples before touching a real cluster.
4. New detector wiring `AGENT.k8s-scope-violation` into `run.py`'s `Config`/`run_once`, reusing the
   existing `Verdict` vocabulary per §0's table.
5. `ebpf-capture` DaemonSet manifest wrapping existing capture code — no capture-logic changes.
6. Warrant demo wiring (`Resource`/`Delegation` registration, ServiceAccount-to-`subject_id`
   binding) — extends the existing `demo/agents.py` Strands pattern, doesn't need new Warrant code.
7. Scripted violation + negative-test suite (§6, §8) — the actual acceptance gate.

## 10. Implementation notes - where steps 1-4 diverged from this draft

Steps 1-4 (`groundtruth/k8s_audit.py`, `adapters/authorization.py`+`adapters/warrant.py`,
`reconciler/k8s_identity.py`, `reconciler/k8s_scope.py`) are built and tested (37 new tests, full
suite 265 passed/9 skipped - the 9 are pre-existing bpftrace-requiring skips, unrelated). Real
deviations found while implementing, corrected here per this repo's own convention (record a
divergence, don't silently paper over it):

- **`Decision` is agentwatch's own local enum**, not an import of `warrant.models.Decision` - §0's
  comment implied importing it directly. agentwatch declares zero dependencies on principle
  (pyproject.toml, BUILD_NOTES.md) and doesn't reach into a sibling repo's package for its own
  event shape; the string values are identical so mapping is a passthrough either way.
- **`adapters/warrant.py` uses stdlib `urllib.request`**, not `httpx` - same zero-dependency reason.
  Confirmed against the real handler: `warrant`'s `/audit/log` (`main.py:155`) needs no new route,
  returns `full_log()` rows verbatim as `{id, timestamp, subject, principal, action, resource,
  decision, policy, facts, reason, obligation_id}` (note: `subject`/`resource`, not `subject_id`/
  `resource_id` - the HTTP response renames the model's field names).
- **`resource_id` is the plural K8s API form** (`"configmaps:default/agent-config"`), not the
  singular illustrative form §6's steps use (`"configmap:default/agent-config"`). There is no
  singular anywhere in a real K8s audit record to recover - `objectRef.resource` is always plural.
  Whoever wires §6's demo MUST register Warrant `Resource`s using the plural form or every
  comparison silently fails to match two strings that were never going to be equal.
- **`REQUIRE_APPROVAL` grants are treated as "no grant"** for this detector's CONFIRMED verdict -
  not specified in §0's table. Reconciling obligation-discharge is Warrant's own job
  (`warrant/audit.py`'s `reconcile()` already does exactly this for its own domain); duplicating it
  here would be redundant, not a missing feature.
- **NONE is not a candidate-level verdict this build produces**, despite §0's table listing it as
  one. Realized instead as a whole-plane condition: `run.py` simply doesn't run this detector at
  all when `Config.warrant_grants` is `None`/empty - the same "None = not collected, contributes
  nothing" contract every other optional plane in `Config` already uses (`instructions_loaded_path`
  etc.), not a special case invented for this one.
- **A grant only authorizes an action at or after its own timestamp** (`grant.ts <= event.ts`) -
  not stated in §0/§2, added because without it a grant issued *after* an unauthorized action
  would retroactively launder it. Regression-pinned:
  `test_grant_issued_after_the_action_does_not_retroactively_authorize_it`.
- **K8s audit JSON has no ausearch-style dialect problem** - `audit_log.py`'s two-dialect handling
  doesn't have an analog here; `audit.k8s.io/v1` is one stable JSON shape, so
  `test_k8s_audit_parser.py` doesn't carry the dialect-fixture weight `test_audit_log_parser.py`
  does. Noted so a future reader doesn't go looking for a dialect bug class that doesn't exist here.

**Still out of scope, correctly**: build order steps 5-7 (the eBPF DaemonSet manifest, the real
Warrant demo wiring, and the actual `kind`-cluster acceptance run per §8) need devhost's `--vantage`
environment and a live Warrant process - neither available for this hands-off pass.
