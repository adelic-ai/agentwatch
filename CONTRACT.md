# Oversight-Component Contract (v0.2)

**Status:** draft, normative. **Audience:** the CageTheAgent deployment stack, agentwatch (reference
impl), and any alternative oversight provider.

**v0.2 change:** adds §1a, an OPTIONAL third input plane (`AuthorizationAdapter`) for components
that also reconcile against a declared-authority record, not just declared intent. Additive only —
a v0.1-conformant component (Plane A + Plane B alone) remains fully conformant under v0.2; nothing
in §1/§2/§3 changed. See K8S-DESIGN.md §0 for the reasoning.

## Purpose

The Enterprise LLM Deployment stack depends on **this contract**, not on agentwatch. Any component
that satisfies it is a conformant oversight provider; **agentwatch is the reference implementation.**
This is precisely what makes the oversight layer swappable — a vendor SIEM, an Entra/DSC-v3 adapter,
or a future detector can fill the same slot by conforming here.

```
Deployment stack (CageTheAgent)
     │ produces two planes (+ OPTIONAL third)      consumes findings
     ▼                                                   ▲
 ┌──────────────────── OVERSIGHT CONTRACT ───────────────────┐
 │ IN:  TranscriptAdapter  +  GroundTruthAdapter              │
 │      + OPTIONAL AuthorizationAdapter (§1a)                 │
 │ OUT: Findings{ verdict ∈ CONFIRMED|GAP|NONE|UNEVALUABLE,   │
 │               attribution, reason, score }                 │
 │      + OPTIONAL canon guarantee tier                       │
 └───────────────────────────────────────────────────────────┘
     ▲ reference impl                 ▲ alternative impls
  agentwatch (merged whole)      vendor SIEM / Entra-DSC / OTEL-bridge
```

## 1. The two input planes

A conformant component consumes two telemetry planes about one governed agent session.

### Plane A — Transcript (self-report; LOW trust)
What the agent *claims* it did. Agent-authored → forgeable → **never** trusted as ground truth; used
only to establish authorizing **intent**.

```python
class TranscriptAdapter(Protocol):
    def iter_events(self) -> Iterable[NormalizedEvent]: ...

# NormalizedEvent (normative fields)
#   kind: TOOL_USE | REASONING
#   ts: float
#   tool_use_id: str | None        # for TOOL_USE
#   tool_name: str | None
#   authorizing_span: tuple | None # the intent window this event authorizes
#   raw_ref: Any                   # back-pointer to the source record
```

### Plane B — Ground truth (OS telemetry; trust = f(substrate))
What the agent *actually* did, from OS audit telemetry captured **outside** the agent. Trust tier
depends on substrate (§4).

```python
class GroundTruthAdapter(Protocol):
    def iter_events(self) -> Iterable[GroundTruthEvent]: ...
    def plane_trust(self) -> PlaneTrust: ...   # UNFORGEABLE | HOST_SHARED | SELF_REPORTED

# GroundTruthEvent (normative fields)
#   kind: EXEC | CLONE | DROP_LAN | ...
#   pid, ppid, uid: int
#   ts: float
#   exe, comm: str
#   args: tuple[str, ...]
#   extra: Mapping                 # subj (confinement label), dev, etc.
```

- MUST provide `EXEC` with pid/ppid/uid/ts/exe.
- **SHOULD provide `CLONE`/fork events.** Without them ancestry is incomplete and more actions fall
  to `UNEVALUABLE` (§3, §Ancestry). Recording clone is the fix for the fork-gap (see the stack's
  `warden` auditd rule + `phase1a/PROOF.md`).

### Supplying Plane B: the `elevation_prefix`-injection pattern

Loading an eBPF probe needs `CAP_BPF`/root, but the reconciler itself must not — an unprivileged
process parsing attacker-adjacent transcript input is the correct privilege boundary. The reference
implementation's capture module (`agentwatch/groundtruth/ebpf_capture.py`) resolves this by taking
the elevation as a plain, caller-supplied argument rather than ever invoking `sudo` (or anything
privilege-raising) itself:

```python
from agentwatch.groundtruth.ebpf_capture import run_capture

events, stats = run_capture(
    duration_s=30,
    elevation_prefix=("sudo", "-n"),   # or (), if the caller already runs as root
)
config = Config(ground_truth_events=events)   # fused additively with any file-plane events
```

This is a general pattern for any orchestrator supplying Plane B, not something specific to one
caller: the component that decides **what** to run (agentwatch) never decides **with what
privilege**; the privilege decision is made in exactly one place the orchestrator controls and can
audit, and passed in as data. `warden`, the reference orchestrator, supplies `elevation_prefix` from
its own `warden/privilege.py` and feeds `run_capture`'s events straight into `Config` this same way.
An alternative orchestrator plugs in identically — its own audited elevation decision, the same two
calls. agentwatch's own CLI (`agentwatch --ebpf`) is one such caller: it needs no orchestrator at
all, and supplies the same `("sudo", "-n")` shape as its own default.

### §1a. The optional third plane — Authorization (K8S-DESIGN.md §0)

A grant is neither Plane A nor Plane B, and stretching either to fit it would misrepresent it: not
the agent's self-report (it's an independent policy engine's own decision, never agent-authored),
and not raw telemetry needing a parser (it's already a structured decision record, e.g. a `warrant`
`AuditRecord` row). A component MAY additionally consume this plane to check ground truth against
**declared authority**, not just **declared intent**:

```python
class AuthorizationAdapter(Protocol):
    def iter_grants(self) -> Iterable[GrantEvent]: ...

# GrantEvent (normative fields)
#   subject_id: str        # the agent identity a decision was made about
#   action: str
#   resource_id: str
#   decision: Decision     # PERMIT | REQUIRE_APPROVAL | FORBID
#   ts: float
#   raw_ref: Any
```

- **OPTIONAL.** A component consuming only Plane A + Plane B remains fully conformant (§5) without
  ever implementing this. Nothing here changes base conformance.
- A component that DOES consume it MUST reuse the §3 verdict vocabulary for authorization-scope
  findings rather than invent a parallel one. Reference technique: `AGENT.k8s-scope-violation`
  (`agentwatch/reconciler/k8s_scope.py`) — `CONFIRMED` for ground truth with no matching PERMIT (or
  a matching FORBID); `GAP` for a PERMIT whose entailed action never shows up in ground truth;
  `UNEVALUABLE` when identity correlation to a `subject_id` fails.
- `REQUIRE_APPROVAL` MUST NOT be treated as authorizing on its own, and its obligation-discharge
  question MUST NOT be re-reconciled here — that belongs to whichever authorization engine issued
  the grant (e.g. `warrant`'s own `audit.py:reconcile()` already does this for its domain; see that
  module's docstring). Duplicating it would be redundant, not a missing feature.
- **The authorization engine owes this plane nothing new to be conformant with.** The reference
  adapter (`agentwatch/adapters/warrant.py`) is a pure consumer of `warrant`'s pre-existing
  `/audit/log` endpoint — no route, schema, or code changed on the authorization-engine side. An
  authorization engine MUST NOT become an inline enforcement gateway for the ground-truth plane it's
  being checked against (K8S-DESIGN.md §2) — that collapses the independence this plane exists for,
  the same self-report problem Plane A vs. Plane B already exists to avoid.
- Ground-truth events with no natural `(action, resource_id)` shape (e.g. a raw process exec) MAY be
  translated into one before reconciliation, rather than reconciled by a second matching engine —
  reference: `reconciler/k8s_scope.py:exec_events_as_actions`, which reframes an exec as
  `action="exec", resource_id=f"process:{comm}"` so it's checked through the same matching path as
  any other action.

## 2. The reconciler (component core)

Consumes `(transcript, ground_truth, agent_uid, config)` → yields `Finding`s. The reference impl
reconciles process-tree ancestry (Plane B) against `tool_use` intent (Plane A) within a session
subtree scope. Alternatives may reconcile differently, as long as outputs conform.

## 3. Output — the Verdict vocabulary (NORMATIVE)

Every `Finding` carries exactly one verdict:

| Verdict | Meaning | Source |
|---|---|---|
| `CONFIRMED` | An action with no authorizing intent, on a channel that **is** collected. | canon vocab |
| `GAP` | An entailed counterpart is absent while its channel **is** collected ("it happened, we didn't record it"). | canon vocab |
| `NONE` | The self-report plane structurally **cannot** see this, so its silence proves nothing. **A conclusion.** | canon vocab |
| `UNEVALUABLE` | The reconciler did **not/could not look** — ground truth insufficient (e.g. ancestry unknowable). **NOT a conclusion.** | local extension |

```python
# Finding (normative)
#   id: str
#   technique: str            # e.g. "AGENT.orphan-exec"
#   event_ref: Any
#   verdict: Verdict
#   attribution: {matched_tool_use_id?: str, matched_pid?: int} | None
#   reason: str
#   score: float
#   plane_trust: PlaneTrust   # copied from the ground-truth adapter
```

**Ancestry note.** A process that forks and never execs has no exec record; its children carry a
`ppid` the tree never saw. Such an action is `UNEVALUABLE` (unknowable), **distinct from** `NONE`
(structurally-invisible-but-concluded) and from ambient noise (traced to a non-runtime origin — a
conclusion). Recording clone (Plane B SHOULD) shrinks the `UNEVALUABLE` set; whatever remains is
reported honestly rather than dropped.

## 4. Trust tiers (substrate-dependent)

`plane_trust()` reflects where Plane B runs:

| Tier | Where | Verdict weight |
|---|---|---|
| `UNFORGEABLE` | audit plane in a VM kernel **outside** the agent's container (container-in-VM) | trustworthy |
| `HOST_SHARED` | audit plane on a host shared with the agent's container | weaker |
| `SELF_REPORTED` | telemetry the agent could author (agent-emitted OTEL) | **not** ground truth — the Roblox Ring-5 gap |

A component SHOULD stamp findings with the tier; the stack SHOULD refuse to grant a high canon
guarantee on `SELF_REPORTED`.

## 5. Conformance rules (what makes an alternative pluggable)

A component is conformant iff:

1. It consumes Plane A + Plane B via the adapter interfaces. (Plane A′/§1a is OPTIONAL — omitting
   it never affects conformance.)
2. It emits `Finding`s using the verdict vocabulary in §3.
3. **`UNEVALUABLE` is never rolled into `CONFIRMED`/clean/coverage counts.** (anti-completion-theater invariant)
4. It **fails open, not blind**: if it cannot scope the session (e.g. no runtime pid found), it
   evaluates everything rather than silently passing.
5. Attribution is **conservative**: never assert a `tool_use`↔process link it has not earned; unearned → `attribution = None`.
6. It is **detective-only**: never acts, only surfaces.

## 6. Optional canon conformance (guarantee tier)

A component MAY project `Finding`s into canon's verdict/provenance/fidelity contracts. If it does:

- The guarantee **tier is EARNED by canon's checks, never asserted.** `well_formed` is the current
  ceiling; `bounded`+ requires calibrated recall.
- `UNEVALUABLE` is a local extension and **MUST NOT** be emitted as a canon verdict; carry it as
  component-local metadata.
- **canon is an OPTIONAL dependency** — the finding pipeline MUST run without it (guarded import).

## 7. Interface summary (what each side owes)

- **Stack → component:** both plane adapters, `agent_uid`, the session boundary, + OPTIONAL an
  `AuthorizationAdapter` (§1a) if the component consumes one.
- **Component → stack:** a `Finding` stream (+ optional canon verdicts) to the console / SIEM.
