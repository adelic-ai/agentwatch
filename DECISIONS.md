# Decisions

Judgment calls made while building the oversight console, per `CLAUDE.md`'s "when the doc is
ambiguous, decide and proceed" instruction. Newest last.

## Stdlib only, unittest instead of pytest

The build VM has no `pip`/`ensurepip` and no `pandas`/`pytest` preinstalled (confirmed:
`python3 -m ensurepip` → "No module named ensurepip"). Rather than reach out to PyPI to install a
test runner and a dataframe library for what is fundamentally line-oriented log parsing, the whole
console (adapters, parsers, reconciler, detectors, CLI, tests) is pure Python 3.12 stdlib —
`json`, `dataclasses`, `unittest`, `argparse`, `sqlite3` (unused so far, kept in reserve for the
findings store if `findings.jsonl` ever needs indexed queries). Tests run via
`python3 -m unittest discover -s tests`. This also means the detector has zero supply-chain
surface — appropriate for a security-monitoring tool. Rejected alternative: install pandas (as
claudescope's `extract.py` does) for the web-viewer timeline; not worth a network dependency for
what a `dict`/`list` comprehension does in a few lines.

## Orphan reconciler: authorization is per-pid-timestamp and transitive, not tool-name-filtered

The transcript carries no PIDs, so a `tool_use` can never be matched to a specific process by ID
(design doc §4 acknowledges the two planes are "different granularities"). The model implemented
in `reconciler/orphan.py`: a process is "authorized" if *its own* exec syscall timestamp falls in
`[tool_use.ts, tool_use.ts + window]` for *any* tool_use that session; authorization is transitive
down the process tree via the ancestry walk, so a slow grandchild spawned well outside the window
still clears if its nearest ancestor was itself authorized. Rejected alternative: restrict
"authorizing" events to Bash-like tool names only. The design doc's own phrasing is "no ancestor
tool_use" (§3.1), not "no ancestor Bash tool_use" — narrowing it is a second heuristic stacked on
an already-heuristic time correlation, and §3's explicit guidance is to prefer under-alerting to a
swamp. Default window is 15s (`DEFAULT_WINDOW_SECONDS`), tunable by the caller; not derived from
the sample telemetry (which has no agent-uid activity to calibrate against — it's generic
root/system noise, see below) but chosen as generous enough to cover typical subprocess-spawn
latency without being so wide it starts crossing between unrelated tool calls.

`agent_uid` is a required parameter, not defaulted — the design doc scopes this detector to "the
agent-user PID tree" specifically, and a silent default would risk reconciling ambient system
noise (cron, systemd, other login sessions) as if it were agent behavior. Confirmed against the
real `audit.log.sample`: it contains no agent-uid activity at all (only uid 0 and a human
"user.guest" login), so it cannot exercise the orphan/legit-burst distinction — it's used only to
prove the *parser* against real auditd output. The reconciler itself is proven with synthetic
fixtures per design doc §8 step 3 (`tests/test_orphan_reconciler.py`): a planted orphan is flagged,
a three-level legit subprocess burst is not, and a uid-boundary crossing (agent shell → sudo →
agent process) still resolves correctly since the process tree is built from *all* ground-truth
events regardless of uid — only the per-event orphan *evaluation* is uid-scoped.
