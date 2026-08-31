# agentwatch

**Oversight for coding-agent sessions of any kind** — interactive freeform dev and hands-off
autonomous runs alike; any situation where an LLM coding agent acts on a machine. agentwatch
reconciles what an agent *said* it did — its transcript — against what it *actually* did — OS audit
telemetry captured outside the agent — and surfaces the actions that have no authorizing intent
behind them. An optional Kubernetes extension does the same reconciliation one level up: what an
agent actually did on a cluster (K8s API audit log + eBPF) against what an authorization engine
actually granted it — validated against a live cluster, **[see the demo](demo/k8s/README.md)**.

It is **detective-only**: it never blocks, kills, or acts. It watches, and it is quiet by default —
it reports exceptions, not activity.

```
   agent transcript  ─┐                           ┌─►  findings.jsonl
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

## Install

```bash
pip install -e .          # or: uv sync
agentwatch --help
```

No third-party runtime dependencies. Python ≥ 3.10.

## Try it now — no infra required

The repo ships a self-contained fixture set (`tests/fixtures/e2e/`) — a transcript, an audit log, and
a journal — so you can see a real reconciliation with no VM, no container, and no warden. One of the
two audit-log execs has an authorizing `tool_use` behind it; the other doesn't:

```bash
agentwatch \
  --agent-uid 3000 \
  --transcript tests/fixtures/e2e/session.jsonl \
  --audit-log  tests/fixtures/e2e/audit.log \
  --findings   /tmp/findings.jsonl

cat /tmp/findings.jsonl
```

```
[agentwatch] 1 new finding(s):
  - orphan_syscall   orphan exec: pid=800 exe=/usr/bin/nc comm=nc - no ancestor tool_use in window
```

`echo legit` was authorized by the session's one `Bash` tool_use and produced nothing; `nc -e /bin/sh`
has no ancestor `tool_use` in its window and comes back `CONFIRMED`. That's the whole mechanism, on
bundled fixture data, with no trust claim attached (no `--plane-trust` was passed, so the finding
carries none). Point it at a real transcript and a real audit log next — see Quickstart below — once
you're ready to attach one.

## What it trusts, what it needs, where it has to run

agentwatch says how much to trust a finding on the finding itself, via a **substrate trust tier**
(`--plane-trust`) — and that tier is a direct function of *where* the ground-truth capture and
agentwatch itself run relative to the agent. Full trust-tier table, the three things agentwatch
needs to produce a trustworthy finding, and the placement guidance that determines which tier you
get: **[`docs/TRUST.md`](docs/TRUST.md)**.

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

## Quickstart — real deployment

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
- `--ebpf` — capture the ground-truth plane itself via bpftrace (`sudo -n`, `--ebpf-duration` seconds),
  with no external orchestrator required; fuses additively with `--audit-log`/`--journal` if given.
- `--plane-trust` — declare the substrate tier (see `docs/TRUST.md`); omit for no claim.

Deployment cadence (interactive vs. hands-off vs. the narrow kernel-root case) is covered in
**[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)**.

## The contract — agentwatch is one implementation, not the interface

A deployment stack should depend on the **oversight contract** ([`CONTRACT.md`](CONTRACT.md)), not on
agentwatch specifically. The contract fixes: two required input planes (a `TranscriptSource` and a
`GroundTruthParser`), an OPTIONAL third (`AuthorizationAdapter` — see Kubernetes extension below),
the four-verdict output vocabulary, the trust tiers, and an optional guarantee backend. Anything
that satisfies it — a SIEM adapter, an identity-platform integration, a different detector — is a
drop-in replacement. `agentwatch/contract.py` is that surface in code; `tests/test_contract.py` is
the conformance check. agentwatch is the reference implementation.

## Kubernetes extension

An OPTIONAL third input plane (CONTRACT.md §1a): reconcile K8s ground truth (API-server audit log +
eBPF process capture) against what an authorization engine actually granted, not just what the
agent claims. Base conformance (transcript + OS ground truth alone) is unaffected — this is
additive, not a replacement.

- **Design + build order:** [`K8S-DESIGN.md`](K8S-DESIGN.md).
- **Working demo, validated against a live cluster:** [`demo/k8s/README.md`](demo/k8s/README.md) —
  real `kind` cluster, real in-cluster `warrant` instance, real eBPF DaemonSet; an authorized action
  produces no finding, an unauthorized one is `CONFIRMED`, from two independent ground-truth sources
  reconciled through one detector.

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
  adapters/               transcript-plane: claude_code, gemini_cli (+ base interface)
                          + authorization plane (optional, CONTRACT.md §1a): authorization.py
                          (the Protocol), warrant.py (reads a live warrant instance)
  groundtruth/            ground-truth parsers: audit_log (auditd), journald (DROP-LAN),
                          ebpf(_capture) (bpftrace), k8s_audit (K8s API-server audit log)
  reconciler/
    process_tree.py      pid/ppid tree from exec+clone events (bridges the fork gap)
    runtime_scope.py     session-subtree scoping; is_unevaluable() structural test
    orphan.py            the orphan-exec reconciler + unevaluable pass
    verdict.py           CONFIRMED / GAP / NONE / UNEVALUABLE
    divergence.py        stated-vs-actual tool divergence
    parse_health.py      transcript-parse reliability gating
    k8s_identity.py      cgroup/K8s-username -> warrant subject_id correlation
    k8s_scope.py         K8s-vs-warrant-grant reconciler; exec_events_as_actions translation
  detectors/             lan_reach, self_mod, agent_flag, instructions_loaded, trifecta (stub)
  findings.py            the Finding model + append-with-dedup store + plane_trust stamping
  run.py                 run_once(config) — the batch orchestration core
  cli.py                 the agentwatch command
  canon_emit.py          optional canon guarantee projection (guarded import)
web/render_timeline.py   optional static-HTML transcript timeline viewer
demo/k8s/                K8s extension demo — kind cluster + in-cluster warrant + eBPF DaemonSet,
                          validated against a live cluster; see K8S-DESIGN.md and its own README
tests/                   unittest; a private real-telemetry acceptance set is skipped when absent
```

## Documentation

- **[`docs/TRUST.md`](docs/TRUST.md)** — the substrate trust-tier table, what agentwatch needs to
  produce a trustworthy finding, and the placement guidance (container-in-VM vs. shared-host vs.
  self-reported) that determines which tier a deployment earns.
- **[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)** — deployment modes: free-form dev, hands-off
  workloads, the narrow kernel-root case where process reconciliation stops applying, and how the
  Kubernetes extension is a genuinely different mode rather than a variant of these.
- **[`docs/STATUS.md`](docs/STATUS.md)** — read this before relying on the tool: what's calibrated,
  what isn't, and why the Kubernetes extension's status is evidenced differently (live-validated,
  not synthetic-only).
- **[`CONTRACT.md`](CONTRACT.md)** — the normative oversight contract: the two required planes, the
  optional third (`AuthorizationAdapter`), the verdict vocabulary, trust tiers, conformance rules.
- **[`K8S-DESIGN.md`](K8S-DESIGN.md)** — the Kubernetes extension's design and build order.
- **[`demo/k8s/README.md`](demo/k8s/README.md)** — the Kubernetes extension's working demo, run for
  real against a live cluster.

## License

Apache-2.0. See [LICENSE](LICENSE).
