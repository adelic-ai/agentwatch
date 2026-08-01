# agentwatch

A quiet-by-default oversight console for a hands-off autonomous coding agent: it reconciles what the
agent *said* it did (its transcript) against what it *actually* did (OS audit telemetry), and surfaces
only actions with no authorizing intent. Three modes, one of which is new code:

1. **Silent detector** *(this repo's new work)* - watches the agent's telemetry, surfaces
   exceptions only.
2. **Peek** - the parsed-transcript timeline for the *current* session.
3. **History** - the same timeline, for *past* sessions, with the work repo's git commits
   interleaved.

Peek and History are one viewer (`web/render_timeline.py`) at different scope; the detector
(`agentwatch/`) is the actual new build. See `DECISIONS.md` for every judgment call made
along the way, and `NEEDS-HUMAN.md` for anything that needed a human (empty = nothing has).

## Status & limitations

**Work in progress — not yet a reliable detector.** What is real, measured on this system's own
first run:

- **False-positive side: effective, on real data.** v2's scoped reconciler produces **0 CONFIRMED
  orphans** on a fully benign run — down from **83** in v1 — via *structural* attribution (session
  scoping + CONFIRMED/GAP/NONE verdicts), not threshold tuning. See "v2: fixing the 83" below.

What is **not** yet proven, and should not be assumed:

- **Recall is untested against real attacks.** Only *synthetic* planted-orphan cases prove it fires.
  An action the transcript plane can't authorize lands in `NONE` (no claim) — i.e. it could be
  *missed*, not caught. Closing this needs real adversarial agent telemetry.
- **One benign run.** No measured precision/recall across diverse runs — nothing here is
  actuarial-grade yet.
- **Attribution is inferred, not instrumented.** The tool_use↔process linkage is heuristic (subtree
  + time window), not a deterministic correlation ID — sound because it is conservative, but that
  ceiling caps how much it can safely catch.

Detective only: it never acts, only surfaces.

## Layout

```
agentwatch/
  events.py              NormalizedEvent / GroundTruthEvent - the shapes everything else reads
  adapters/
    base.py              TranscriptAdapter interface
    claude_code.py        Claude Code .jsonl adapter (defensive - see module docstring)
  groundtruth/
    audit_log.py          auditd text-log parser -> exec GroundTruthEvents
    journald.py            journal.jsonl parser -> DROP-LAN GroundTruthEvents
  reconciler/
    process_tree.py        pid/ppid tree from ground-truth exec events
    runtime_scope.py        v2: agent-session subtree scoping + runtime/runtime-internal
                              classification (design doc v2 §2) - see DECISIONS.md
    verdict.py               v2: CONFIRMED/GAP/NONE verdict enum (design doc v2 §3)
    parse_health.py          v2: skip-rate + tool_use-vs-exec drift gating (design doc v2 §4)
    orphan.py               orphan-syscall detector (design doc §3.1 / §4 - the risk);
                              reconcile_orphans_scoped() is what run.py calls in v2
    divergence.py            reasoning-vs-action divergence detector (design doc §3.2)
  detectors/
    lan_reach.py            any DROP-LAN event -> a finding
    self_mod.py              content-hash baseline diff over the agent's own config
    agent_flag.py             surfaces NEEDS-HUMAN.md entries verbatim
    trifecta.py                lethal-trifecta stub (design doc §7 non-goal)
  findings.py               Finding model + findings.jsonl store (id-based dedup)
  timeline.py               merges transcript + findings + git log for peek/history
  state.py                   tiny persisted JSON (currently: the self-mod baseline)
  run.py                     run_once(config) - the batch orchestration core
  notifier.py                 quiet-when-empty terminal notifier
  cli.py                       argparse entrypoint
web/
  render_timeline.py         static-HTML peek/history renderer, claudescope-styled
tests/                       unittest, mirrors the package layout; tests/fixtures/ has a
                              real audit.log sample, synthetic journald/transcript fixtures, and
                              a full tests/fixtures/e2e/ set exercising every detector at once
(fixtures/                   the real-telemetry acceptance dataset - this system's own benign run -
                              is kept PRIVATE and is not in this repo; tests/test_acceptance_fixtures.py
                              skips without it. See "v2: fixing the 83" below.)
```

## Running it

No external dependencies - stdlib only (see DECISIONS.md for why: no pip/pytest/pandas were
available on the build environment, and it also means zero supply-chain surface for a security tool).

```sh
# one detector pass
python3 -m agentwatch.cli \
  --agent-uid "$(id -u AGENT_USER)" \
  --transcript-glob '~/.claude/projects/*/*.jsonl' \
  --audit-log /path/to/audit.log \
  --journal /path/to/journal.jsonl \
  --needs-human /path/to/NEEDS-HUMAN.md \
  --findings findings.jsonl \
  --state agentwatch_state.json

# same, but polling every 30s instead of running once
python3 -m agentwatch.cli ... --watch --interval 30
```

Prints nothing when there's nothing new to say. When there is, one line per new finding to
stderr, and it's appended to `findings.jsonl`.

```sh
# peek: current session
python3 web/render_timeline.py \
  --transcript /path/to/CURRENT_SESSION.jsonl \
  --findings findings.jsonl --repo . --out peek.html

# history: every past session
python3 web/render_timeline.py \
  --transcript '~/.claude/projects/*/*.jsonl' \
  --findings findings.jsonl --repo . --out history.html
```

## Testing

```sh
python3 -m unittest discover -s tests -v
```

`tests/fixtures/audit_logs/audit.log.sample` is a real 300-line auditd sample (copied in verbatim) -
it proves the auditd parser against real output, but it's generic system noise with no agent-uid
activity, so it can't exercise the orphan-vs-legit-burst distinction itself (see DECISIONS.md). That's
what `tests/test_orphan_reconciler.py`'s synthetic fixtures are for, per design doc §8 step 3: a
planted orphan is flagged, a multi-level legit subprocess burst is not.
`tests/fixtures/e2e/` + `tests/test_run.py` run every wired-up v1 detector together in one
`run_once()` call, including the dedup-on-rerun behavior. It predates session scoping and has no
runtime-pid exec in its ground truth, so it exercises v2's documented fail-open fallback (see
DECISIONS.md) rather than the scoped path - `tests/test_orphan_verdict.py` and
`tests/test_acceptance_fixtures.py` (against the real `fixtures/`, kept private - it skips when they
are absent, as in this public repo; see "v2: fixing the 83" below) cover the scoped/verdict behavior
directly.

## v1 scope

Built (design doc §7): Claude adapter; the reconciler (orphan + divergence); LAN-reach, self-mod,
and agent-flag detectors; `findings.jsonl` + a terminal notifier; peek/history overlay.

Not built, on purpose: the lethal-trifecta CEP (interface stubbed in `detectors/trifecta.py`),
a Gemini adapter, real-time streaming (batch/poll only), and any enforcement/blocking - this is
detective only, it never acts, only surfaces. Still true in v2.

## v2: fixing the 83

Replayed against `fixtures/` - the real telemetry from this system's own first (v1) run, kept
private and not included in this public repo - the orphan reconciler flagged **83 false positives**
on entirely benign activity (true answer ~0).
Root cause: it evaluated every uid-1000 exec system-wide, with no notion of "the agent's session"
versus "everything else uid 1000 ever touched" - login/provisioning noise, and the agent runtime's
own housekeeping execs (`git status`, ripgrep, an npm version check), got time-window-checked
against the transcript exactly like real tool-call output, and failed, because nothing in a
transcript ever authorizes them.

v2 fixes this with `reconciler/runtime_scope.py`: find the agent runtime's own processes (`claude`/
`claude.exe`/`node`), scope evaluation to their descendant subtree only (everything else is out of
scope entirely, not even a suppressed candidate), and classify unmatched-but-in-scope execs against
a small documented "runtime-internal" allowlist (git/rg/npm/node/env, a POSIX-shell-not-bash) so
Claude Code's own housekeeping gets a `NONE` verdict instead of `CONFIRMED` - while an unexplained
exec (say, a compromised runtime spawning something unrecognized) still is. `reconciler/verdict.py`
replaces the old binary `is_orphan` with this CONFIRMED/GAP/NONE vocabulary; `reconciler/
parse_health.py` adds a safety net so a Claude Code schema change that silently breaks the
transcript parser downgrades everything to NONE instead of manufacturing false CONFIRMEDs.

`tests/test_acceptance_fixtures.py` is the "definition of done" per design doc v2 §5: all 83 of
v1's flagged pids reclassify off CONFIRMED, CONFIRMED orphans across the *entire* real audit.log
are 0, and every pre-existing synthetic test (planted orphan still CONFIRMED, legit burst still
clear) stays green. See `DECISIONS.md`'s `## v2: ...` entries for the reasoning behind each call.
