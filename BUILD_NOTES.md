# Build note: Agent oversight console

TL;DR for a human catching up without reading nine commits and a decision log: what this is, what
got built, the calls that needed judgment, and where to look for more.

## What this is

An oversight console for a hands-off autonomous coding agent, built from
`~/inbox/oversight-console-design.md`. The design doc frames three modes but only one is new code:

- **Silent detector** *(the actual build)* — watches the agent's telemetry, says nothing unless
  something's actually wrong.
- **Peek** / **History** — a parsed-transcript timeline, for the live session or past ones. The
  doc's intent was "reuse claudescope, don't build a UI" — see *Deviation* below for why a small
  renderer got built anyway.

## What got built (v1, matches design doc §7 scope exactly)

| Piece | File(s) | What it does |
|---|---|---|
| Transcript adapter | `adapters/claude_code.py` | Defensively parses Claude Code's `.jsonl`, tolerant of the schema drift the sample docs warn about |
| Ground-truth parsers | `groundtruth/audit_log.py`, `groundtruth/journald.py` | auditd text records → exec events; journald → DROP-LAN events |
| Orphan reconciler | `reconciler/process_tree.py`, `reconciler/orphan.py` | The novel, highest-fidelity detector: a security-relevant exec with no ancestor `tool_use` in a time window |
| Divergence detector | `reconciler/divergence.py` | Stated tool vs. actually-called tool, lexical not semantic |
| LAN-reach / self-mod / agent-flag | `detectors/*.py` | The three simpler, single-plane checks |
| Lethal-trifecta | `detectors/trifecta.py` | Stub only — explicit v1 non-goal |
| Findings + notifier | `findings.py`, `notifier.py` | Dedup'd `findings.jsonl`; prints nothing when there's nothing to say |
| CLI | `cli.py`, `run.py` | `--once` or `--watch --interval N` |
| Peek/history | `timeline.py`, `web/render_timeline.py` | Merges transcript + findings + `git log` into one static HTML page |

**64 tests, all passing**, stdlib-only (`unittest`) — no `pip`/`pytest`/`pandas` were available on
the build VM, so the whole thing has zero external dependencies, which is arguably the right call
for a security-monitoring tool anyway.

## The five calls that needed judgment

Full reasoning for each is in `DECISIONS.md`; short version:

1. **Orphan authorization is transitive and not tool-name-restricted.** A process is "authorized"
   if its own exec timestamp lands inside a `[tool_use.ts, tool_use.ts+window]` window for *any*
   tool_use that session, and descendants inherit that authorization down the process tree. Chose
   this over restricting to Bash-only tool_use calls, because the design doc's own guidance is to
   under-alert rather than swamp the human, and a second heuristic stacked on an already-heuristic
   correlation cuts the wrong way.
2. **Divergence is lexical, not semantic.** A reasoning block only makes a checkable claim when it
   names a tool literally. A real semantic judge would need an LLM call, which reintroduces the
   self-judge circularity the design doc explicitly wants to avoid.
3. **Self-mod needs a persisted baseline; agent-flag doesn't.** "Did this change" is inherently a
   two-point-in-time question; a `NEEDS-HUMAN.md` entry's dedup key is a hash of its own verbatim
   text, so it doesn't need separate state at all.
4. **Trifecta stays a stub.** The design doc defers it explicitly; the semantics it'd need (what
   counts as "private data"? does the accumulation window decay?) aren't specified, and inventing
   that policy unasked felt like the wrong kind of autonomy.
5. **The peek/history "reuse claudescope" deviation.** `claudescope/web/*.html` turned out to be
   static write-ups with no `<script>` tag in sight — not a live timeline viewer. Rather than skip
   the overlay or quietly redefine "reuse," built a small renderer (`web/render_timeline.py`) that
   reuses claudescope's actual CSS palette and dark theme for visual continuity, and the same
   generator for both peek and history scopes.

## Validated how

- Synthetic fixtures with a planted orphan and a multi-level legit subprocess burst, per the
  design doc's explicit "prove this before UI" instruction for the reconciler.
- The real 300-line `audit.log.sample` (copied in verbatim), which proved the parser but — being
  generic system noise with no agent-uid activity — couldn't exercise the orphan/legit distinction
  itself; noted honestly in `DECISIONS.md` rather than glossed over.
- `tests/fixtures/e2e/` runs all five wired detectors together in one `run_once()` call, including
  the dedup-on-rerun behavior.
- Fresh `git clone` + `python3 -m unittest discover` in a scratch dir, to make sure nothing depends
  on absolute paths outside the repo.
- Manual smoke tests of the actual CLI binary (`--once` and `--watch`) and the HTML renderer.

## Where to look next

- `README.md` — how to run it.
- `DECISIONS.md` — every judgment call, with the rejected alternative and why.
- `NEEDS-HUMAN.md` — still empty. Nothing hit the bar for "needs a human."
- Commit log (`git log`) — nine atomic commits, one per design-doc build-order step, each with a
  body explaining the *why*.
