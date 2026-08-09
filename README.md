# agentwatch

**Oversight for hands-off autonomous coding agents.** agentwatch reconciles what an agent *said* it
did — its transcript — against what it *actually* did — OS audit telemetry captured outside the agent
— and surfaces the actions that have no authorizing intent behind them.

It is **detective-only**: it never blocks, kills, or acts. It watches, and it is quiet by default —
it reports exceptions, not activity.

```
   agent transcript  ─┐                          ┌─►  findings.jsonl
   (what it SAID)     ├─►   agentwatch   ─────────┤    (orphan execs, divergence, LAN-reach, …)
   OS audit telemetry ┘     reconciler            └─►  one quiet human-facing surface
   (what it DID)
```

## Why

An autonomous agent's own logs are self-reported and therefore forgeable — if the agent (or
something that compromised it) does work it doesn't report, its logs won't show it. agentwatch does
not trust the agent's account. It compares the transcript against an **independent** ground-truth
plane (OS `execve`/`clone` audit records) and asks a single question of every action the agent's
process tree took: *was there an authorizing intent for this?* Actions with none are surfaced.

This is the piece a sandbox needs but rarely has: containment stops the agent from reaching what it
shouldn't; agentwatch tells you what it actually reached.

## What it trusts — and how much

agentwatch is only as trustworthy as its ground-truth plane, and it says so on every finding via a
**substrate trust tier** (`--plane-trust`):

| Tier | Where the audit plane runs | Meaning |
|---|---|---|
| `unforgeable` | a VM kernel **outside** the agent's container (container-in-VM) | the agent cannot forge or erase it — findings are trustworthy |
| `host_shared` | a host shared with the agent's container | weaker: a container escape reaches the plane |
| `self_reported` | telemetry the agent itself emits (e.g. agent-authored OTEL) | **not** ground truth — do not stake detection on it |

The tier is operator-declared, because a log parser cannot infer where its input came from. Omit it
and findings carry **no** trust claim rather than a false one.

## Verdicts

Every reconciled action gets exactly one verdict. The fourth is the one most detectors omit and the
reason this one is honest:

| Verdict | Meaning |
|---|---|
| `CONFIRMED` | an action on a collected channel, with no authorizing intent — a real discrepancy |
| `GAP` | an intended action whose ground-truth counterpart is missing ("it happened, we didn't record it") |
| `NONE` | the transcript plane structurally *cannot* see this class of action, so its silence proves nothing — **a conclusion** |
| `UNEVALUABLE` | the reconciler *could not look* — the ground-truth plane didn't give it enough (e.g. ancestry breaks at a process that forked without exec'ing) — **not a conclusion, and never counted as coverage** |

`UNEVALUABLE` exists so a clean `CONFIRMED` count can never quietly imply coverage the run didn't
actually have. An exec the tool couldn't place is reported as a coverage gap, not silently dropped.

## Install

```bash
pip install -e .          # or: uv sync
agentwatch --help
```

No third-party runtime dependencies. Python ≥ 3.10.

## Quickstart

```bash
agentwatch \
  --agent-uid 1001 \
  --transcript-glob '~/.claude/projects/*/*.jsonl' \
  --audit-log   /var/log/audit/audit.log \
  --plane-trust unforgeable \
  --findings    ./findings.jsonl
```

Runs once and writes new findings (deduped) to `findings.jsonl`. Add `--watch --interval 30` to poll
continuously. Batch/poll, not real-time streaming — by design.

- `--agent-uid` scopes reconciliation to the agent user's process tree (required).
- `--transcript` / `--transcript-glob` — the self-report plane. Claude Code and Gemini CLI adapters
  ship; add a runtime by writing one `TranscriptAdapter`.
- `--audit-log` / `--journal` — the ground-truth plane (auditd text log; journald DROP-LAN records).
- `--plane-trust` — declare the substrate tier (see above); omit for no claim.

## Status — read this before relying on it

**agentwatch is a work in progress, not yet a calibrated detector.** Being precise about what is and
isn't proven is part of the point:

- **False positives — strong on real data, but n=1.** On a benign real run, the scoped reconciler
  produces **0 `CONFIRMED` orphans** (down from 83 in a naive first pass) through *structural*
  attribution — session-subtree scoping and the graded verdicts — not threshold tuning. This is one
  run, not a calibrated false-positive rate across diverse workloads.
- **Recall is unmeasured.** Only *synthetic* planted-orphan cases prove the detector fires. It has
  not been run against real adversarial telemetry (prompt injection, a compromised session), so
  there is **no measured false-negative number**. An action the transcript plane can't authorize can
  land in `NONE` — i.e. it could be missed, not caught.
- **Attribution is heuristic, and that is a ceiling.** Linking a `tool_use` to a process is done by
  process-subtree membership and a time window, not a deterministic correlation ID stamped at the
  source. It is deliberately conservative (it won't assert a link it hasn't earned), which caps how
  much it can safely catch. Raising the ceiling needs instrumented correlation IDs, not more tuning.

In short: today it is a credible **verify-and-audit** surface on top of a real containment boundary —
not something to stake detection on by itself.

## The contract — agentwatch is one implementation, not the interface

A deployment stack should depend on the **oversight contract** ([`CONTRACT.md`](CONTRACT.md)), not on
agentwatch specifically. The contract fixes: two input planes (a `TranscriptSource` and a
`GroundTruthParser`), the four-verdict output vocabulary, the trust tiers, and an optional guarantee
backend. Anything that satisfies it — a SIEM adapter, an identity-platform integration, a different
detector — is a drop-in replacement. `agentwatch/contract.py` is that surface in code;
`tests/test_contract.py` is the conformance check. agentwatch is the reference implementation.

## Optional: canon guarantee tiers

If canon is importable, agentwatch projects each finding into canon's verdict/provenance contracts
and records an **earned** guarantee tier (never asserted — the tier is what canon's checks grant).
canon is a fully optional dependency: with it absent, the finding pipeline runs unchanged and simply
doesn't emit guarantee tiers. `UNEVALUABLE` is an agentwatch-local honesty extension and is
deliberately never emitted as a canon verdict.

## Layout

```
agentwatch/
  events.py              the two normalized shapes everything above an adapter reads
  contract.py            the oversight-contract surface (Verdict, PlaneTrust, the two Protocols)
  adapters/              transcript-plane adapters: claude_code, gemini_cli (+ base interface)
  groundtruth/           ground-truth parsers: audit_log (auditd), journald (DROP-LAN)
  reconciler/
    process_tree.py      pid/ppid tree from exec+clone events (bridges the fork gap)
    runtime_scope.py     session-subtree scoping; is_unevaluable() structural test
    orphan.py            the orphan-exec reconciler + unevaluable pass
    verdict.py           CONFIRMED / GAP / NONE / UNEVALUABLE
    divergence.py        stated-vs-actual tool divergence
    parse_health.py      transcript-parse reliability gating
  detectors/             lan_reach, self_mod, agent_flag, trifecta (stub)
  findings.py            the Finding model + append-with-dedup store + plane_trust stamping
  run.py                 run_once(config) — the batch orchestration core
  cli.py                 the agentwatch command
  canon_emit.py          optional canon guarantee projection (guarded import)
web/render_timeline.py   optional static-HTML transcript timeline viewer
tests/                   unittest; a private real-telemetry acceptance set is skipped when absent
```

## License

Apache-2.0. See [LICENSE](LICENSE).
