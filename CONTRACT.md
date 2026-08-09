# Oversight-Component Contract (v0.1)

**Status:** draft, normative. **Audience:** the CageTheAgent deployment stack, agentwatch (reference
impl), and any alternative oversight provider.

## Purpose

The Enterprise LLM Deployment stack depends on **this contract**, not on agentwatch. Any component
that satisfies it is a conformant oversight provider; **agentwatch is the reference implementation.**
This is precisely what makes the oversight layer swappable — a vendor SIEM, an Entra/DSC-v3 adapter,
or a future detector can fill the same slot by conforming here.

```
Deployment stack (CageTheAgent)
     │ produces two planes                        consumes findings
     ▼                                                   ▲
 ┌──────────────────── OVERSIGHT CONTRACT ───────────────────┐
 │ IN:  TranscriptAdapter  +  GroundTruthAdapter             │
 │ OUT: Findings{ verdict ∈ CONFIRMED|GAP|NONE|UNEVALUABLE, │
 │               attribution, reason, score }                │
 │      + OPTIONAL canon guarantee tier                      │
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

1. It consumes Plane A + Plane B via the adapter interfaces.
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

- **Stack → component:** both plane adapters, `agent_uid`, the session boundary.
- **Component → stack:** a `Finding` stream (+ optional canon verdicts) to the console / SIEM.
