# Agent oversight console

A quiet-by-default oversight console for a hands-off autonomous coding agent, per
`~/inbox/oversight-console-design.md`. Three modes, one of which is new code:

1. **Silent detector** *(this repo's new work)* - watches the agent's telemetry, surfaces
   exceptions only.
2. **Peek** - the parsed-transcript timeline for the *current* session.
3. **History** - the same timeline, for *past* sessions, with the work repo's git commits
   interleaved.

Peek and History are one viewer (`web/render_timeline.py`) at different scope; the detector
(`oversight_console/`) is the actual new build. See `DECISIONS.md` for every judgment call made
along the way, and `NEEDS-HUMAN.md` for anything that needed a human (empty = nothing has).

## Layout

```
oversight_console/
  events.py              NormalizedEvent / GroundTruthEvent - the shapes everything else reads
  adapters/
    base.py              TranscriptAdapter interface
    claude_code.py        Claude Code .jsonl adapter (defensive - see module docstring)
  groundtruth/
    audit_log.py          auditd text-log parser -> exec GroundTruthEvents
    journald.py            journal.jsonl parser -> DROP-LAN GroundTruthEvents
  reconciler/
    process_tree.py        pid/ppid tree from ground-truth exec events
    orphan.py               orphan-syscall detector (design doc §3.1 / §4 - the risk)
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
tests/                       unittest, mirrors the package layout; tests/fixtures/ has the
                              real audit.log.sample, synthetic journald/transcript fixtures, and
                              a full tests/fixtures/e2e/ set exercising every detector at once
```

## Running it

No external dependencies - stdlib only (see DECISIONS.md for why: no pip/pytest/pandas were
available on the build VM, and it also means zero supply-chain surface for a security tool).

```sh
# one detector pass
python3 -m oversight_console.cli \
  --agent-uid "$(id -u agent-username)" \
  --transcript-glob '~/.claude/projects/*/*.jsonl' \
  --audit-log /Users/Shared/agent-telemetry/audit.log \
  --journal /Users/Shared/agent-telemetry/journal.jsonl \
  --needs-human ~/work/NEEDS-HUMAN.md \
  --findings ~/work/findings.jsonl \
  --state ~/.oversight_console_state.json

# same, but polling every 30s instead of running once
python3 -m oversight_console.cli ... --watch --interval 30
```

Prints nothing when there's nothing new to say. When there is, one line per new finding to
stderr, and it's appended to `findings.jsonl`.

```sh
# peek: current session
python3 web/render_timeline.py \
  --transcript ~/.claude/projects/*/CURRENT_SESSION.jsonl \
  --findings ~/work/findings.jsonl --repo ~/work --out peek.html

# history: every past session
python3 web/render_timeline.py \
  --transcript '~/.claude/projects/*/*.jsonl' \
  --findings ~/work/findings.jsonl --repo ~/work --out history.html
```

## Testing

```sh
python3 -m unittest discover -s tests -v
```

`tests/fixtures/audit_logs/audit.log.sample` is the real 300-line sample from
`~/inbox/sample-telemetry/` (copied in verbatim) - it proves the auditd parser against real
output, but it's generic system noise with no agent-uid activity, so it can't exercise the
orphan-vs-legit-burst distinction itself (see DECISIONS.md). That's what
`tests/test_orphan_reconciler.py`'s synthetic fixtures are for, per design doc §8 step 3: a
planted orphan is flagged, a multi-level legit subprocess burst is not.
`tests/fixtures/e2e/` + `tests/test_run.py` run every wired-up v1 detector together in one
`run_once()` call, including the dedup-on-rerun behavior.

## v1 scope

Built (design doc §7): Claude adapter; the reconciler (orphan + divergence); LAN-reach, self-mod,
and agent-flag detectors; `findings.jsonl` + a terminal notifier; peek/history overlay.

Not built, on purpose: the lethal-trifecta CEP (interface stubbed in `detectors/trifecta.py`),
a Gemini adapter, real-time streaming (batch/poll only), and any enforcement/blocking - this is
detective only, it never acts, only surfaces.
