"""Session-subtree scoping + agent-runtime classification (design doc v2 §2).

v1's orphan reconciler scoped itself to "every uid-1000 exec" and asked only "is there an
authorizing tool_use nearby in time." Replayed against this system's own real first run
(`fixtures/`), that produced 83 false positives, all traced to one root cause: scope too broad.
Three concrete shapes, all fixed here:

1. **Login/provisioning noise** (`ssh-keygen`, `locale`, the staging `tar`/`cp`) - real
   agent-uid execs, but they happen *before* any Claude Code process exists, or under a
   completely different ancestry (a provisioning shell, not the agent's own session). No
   tool_use could ever explain them because they're not the agent's session at all.
2. **The agent runtime's own execs** - `claude`/`claude.exe`/`node` re-launching itself. Nothing
   in a transcript "authorizes" the interpreter that's reading the transcript.
3. **Runtime-internal tool execs** - Claude Code runs `git status`, ripgrep searches, and an npm
   self-update check directly (no intervening shell a Bash tool_use could have spawned), plus a
   couple of quick internal one-liners (an IDE-detection probe, a git-identity check) via
   `/bin/sh -c` rather than the `/bin/bash -c` the real Bash tool uses.

`RuntimeScope` answers two questions per exec event: is it even part of the agent's session
(`in_scope`), and if it has no correlating tool_use, is that because it's runtime activity the
self-report plane structurally cannot see (`classify_unmatched` -> NONE), or a genuine unexplained
action (-> CONFIRMED). See `reconciler/verdict.py` for the CONFIRMED/GAP/NONE vocabulary and
`reconciler/orphan.py:reconcile_orphans_scoped` for how this plugs into the time-window check.
"""
from __future__ import annotations

from typing import Iterable, Optional

from agentwatch.events import EXEC, GroundTruthEvent
from agentwatch.reconciler.process_tree import ProcessTree
from agentwatch.reconciler.verdict import Verdict

# The agent runtime binary itself - a documented, swappable set (design doc v2 §2, §6: a future
# Gemini adapter would pair with a different set here, passed in rather than hardcoded elsewhere).
# Matches on `exe` path prefix; `node` additionally matches when its own argv shows it's launching
# `claude` (observed in the real fixture: `node /usr/lib/node_modules/.../claude.exe ...`-style
# re-exec chains), not just any node process (e.g. the npm-version-check below is also a `node`
# invocation, but of npm, not claude - it must NOT match here, or it) would mask itself as "the
# runtime" rather than "something the runtime spawned").
DEFAULT_RUNTIME_EXE_PREFIXES: frozenset[str] = frozenset({
    "/usr/lib/node_modules/@anthropic-ai/claude-code/",
})

# argv markers that identify a `node` process as *being* the runtime rather than something the
# runtime spawned. Parameterized rather than hardcoded because the check is identical across
# node-based CLIs and only the marker differs - see GEMINI_* below and DECISIONS.md G13.
DEFAULT_RUNTIME_ARGV_MARKERS: frozenset[str] = frozenset({"claude"})

# The runtime launcher's BASENAME / comm, for the install shape where it is exec'd DIRECTLY rather than
# as `node …/cli.js`. The npm-global install and the self-contained-binary builds put the launcher at
# `/usr/bin/claude` (comm `claude`), so neither the node_modules prefix above nor the `node`+argv rule
# fires. MEASURED on a warden dev home (claude-code 2.1.231): the runtime execs as comm=claude,
# filename=/usr/bin/claude, with no `node` re-exec at all. Matched on the exe basename OR comm, so it
# catches `/usr/bin/claude` and a bare `claude` alike. Sibling set: GEMINI_RUNTIME_BASENAMES.
DEFAULT_RUNTIME_BASENAMES: frozenset[str] = frozenset({"claude"})

# Binaries Claude Code is known to exec *directly* (no intervening shell) for its own operation,
# never as a delegated tool call - diagnosed from the real 83 false positives: `git` (status/log/
# remote/config, gathering repo context), `rg` (ripgrep, file search/indexing), and the npm
# self-update version check (`env node /usr/bin/npm view ... --prefer-online`, hence both `env`
# and `node` are here alongside `npm` itself - the exec chain hops through both).
DEFAULT_RUNTIME_INTERNAL_NAMES: frozenset[str] = frozenset({"git", "rg", "npm", "node", "env"})

# A POSIX shell (not bash) invoked directly under the runtime, for the runtime's own quick
# one-liners (an IDE-detection probe, a git-identity check observed in the fixture) - distinct
# from `/bin/bash -c`, which is what the real Bash tool spawns. This is a heuristic, not a
# guarantee (see DECISIONS.md): a future Claude Code version could use sh for something a
# tool_use ought to have covered, in which case this would wrongly downgrade it to NONE rather
# than surface it. Kept anyway per the design doc's own steer to prefer under-alerting over a
# swamp, and it's exactly the shape the real false positives took.
DEFAULT_POSIX_SHELLS: frozenset[str] = frozenset({"sh", "dash", "ash"})


def _basename(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    return path.rsplit("/", 1)[-1]


def is_runtime_exec(
    exe: Optional[str],
    comm: Optional[str],
    args: tuple,
    runtime_exe_prefixes: frozenset[str] = DEFAULT_RUNTIME_EXE_PREFIXES,
    runtime_argv_markers: frozenset[str] = DEFAULT_RUNTIME_ARGV_MARKERS,
    runtime_basenames: frozenset[str] = DEFAULT_RUNTIME_BASENAMES,
) -> bool:
    """Does this exec event's *own* process belong to the agent runtime itself?"""
    if exe and any(exe.startswith(prefix) for prefix in runtime_exe_prefixes):
        return True
    # Directly-exec'd launcher (npm-global / self-contained binary): comm/basename IS the runtime,
    # e.g. `/usr/bin/claude`. Covers the install where there is no `node …/cli.js` to match above.
    if comm in runtime_basenames or _basename(exe) in runtime_basenames:
        return True
    if comm == "node" and any(
        marker in a for a in args if isinstance(a, str) for marker in runtime_argv_markers
    ):
        return True
    return False


class RuntimeScope:
    """Per-agent_uid classification of a process tree into session/runtime/out-of-scope.

    Built once per reconciler run from the full (unfiltered) ground-truth event stream - the
    ancestry walk needs every pid, including cross-uid hops, so scoping is a read-only overlay on
    top of `ProcessTree`, not a filter applied before it (see `reconciler/orphan.py`).
    """

    def __init__(
        self,
        ground_truth_events: Iterable[GroundTruthEvent],
        agent_uid: int,
        tree: ProcessTree,
        runtime_exe_prefixes: frozenset[str] = DEFAULT_RUNTIME_EXE_PREFIXES,
        runtime_internal_names: frozenset[str] = DEFAULT_RUNTIME_INTERNAL_NAMES,
        posix_shells: frozenset[str] = DEFAULT_POSIX_SHELLS,
        runtime_argv_markers: frozenset[str] = DEFAULT_RUNTIME_ARGV_MARKERS,
        runtime_basenames: frozenset[str] = DEFAULT_RUNTIME_BASENAMES,
        runtime_internal_argv: frozenset = frozenset(),
    ) -> None:
        self._tree = tree
        self._runtime_internal_names = runtime_internal_names
        self._runtime_internal_argv = runtime_internal_argv
        self._posix_shells = posix_shells
        self._exe_by_pid: dict[int, Optional[str]] = {}
        self._comm_by_pid: dict[int, Optional[str]] = {}
        # A pid can execve more than once (a PATH search records a failed attempt and then the
        # successful one under the same pid), so argv is accumulated as a set rather than
        # last-write-wins - otherwise a failed probe's empty argv can overwrite the real one.
        self._argv_by_pid: dict[int, set] = {}
        self._cgroup_by_pid: dict[int, Optional[str]] = {}
        self._ts_by_pid: dict[int, Optional[float]] = {}
        agent_exec_pids: set[int] = set()
        session_cgroup: Optional[str] = None
        runtime_pids: set[int] = set()
        # When the agent runtime first appears. Used only by `is_unevaluable`: an exec that happened
        # BEFORE the runtime's first exec cannot be a descendant of it, whatever its ancestry looks
        # like, so it is genuinely out of scope rather than unknown. A structural argument, not a
        # heuristic - it is the one thing that can be concluded about a process with no traceable
        # parentage. Accumulated in this loop rather than by re-iterating, because the argument is
        # declared `Iterable` and a caller may hand over a generator.
        #
        # (Caveat, documented rather than papered over: a pid forked by the runtime's *pre-exec*
        # incarnation - between fork and exec - is placed out of scope rather than unevaluable.
        # That window was 4ms wide in the measured capture.)
        runtime_first_ts: Optional[float] = None

        for ev in ground_truth_events:
            if ev.kind != EXEC or ev.pid is None:
                continue
            # Don't let a failed execve (argv=(), pre-exec comm) clobber the identity of the
            # successful one at the same pid.
            if ev.success is not False or ev.pid not in self._exe_by_pid:
                self._exe_by_pid[ev.pid] = ev.exe
                self._comm_by_pid[ev.pid] = ev.comm
                self._cgroup_by_pid[ev.pid] = ev.cgroup
            if ev.args:
                self._argv_by_pid.setdefault(ev.pid, set()).add(tuple(ev.args))
            if ev.uid == agent_uid:
                agent_exec_pids.add(ev.pid)
                self._ts_by_pid[ev.pid] = ev.ts
            if ev.uid == agent_uid and is_runtime_exec(
                ev.exe, ev.comm, ev.args, runtime_exe_prefixes, runtime_argv_markers, runtime_basenames
            ):
                runtime_pids.add(ev.pid)
                if ev.ts is not None and (runtime_first_ts is None or ev.ts < runtime_first_ts):
                    runtime_first_ts = ev.ts
                if session_cgroup is None and ev.cgroup is not None:
                    session_cgroup = ev.cgroup  # the container's cgroup, from the runtime's own exec

        self.runtime_pids: frozenset[int] = frozenset(runtime_pids)
        self._runtime_first_ts = runtime_first_ts
        # No runtime pid found at all for this agent_uid -> we can't tell session activity from
        # ambient noise, so scoping fails *open* (evaluate everything, v1's old behavior) rather
        # than silently going blind. See DECISIONS.md - a security detector should never respond
        # to "I couldn't find what I was looking for" by evaluating nothing.
        self.active: bool = bool(runtime_pids)

        # cgroup-keyed rescue of the fork gap (the fused evidence model — design in warden
        # CANONICAL-SHAPE.md / CAPTURE-CONSTRAINT.md). An exec whose ancestry is UNKNOWABLE (its
        # parent has no exec record — the fork-without-exec / host-root-injection case that
        # `is_unevaluable` handles) but which is in the SESSION's cgroup is, by cgroup membership,
        # inside the container's session — a signal that survives the broken ancestry walk. Rescue it
        # to in-scope so it earns a verdict instead of a silent UNEVALUABLE.
        #
        # GATED on cgroup data being present (`session_cgroup is not None`): with auditd-only telemetry
        # there are no cgroups, so this set is empty and ancestry stays the sole basis — the pre-fusion
        # behavior, so every existing test is unaffected. Deliberately NARROW: the same conditions as
        # `is_unevaluable` (unknowable parent, not provably older than the runtime), NEVER the
        # definitively traced-out noise (a known non-runtime parent — the `su - agent` login shell),
        # so the login/provisioning out-of-scope conclusions stay intact.
        #
        # Coarseness (recorded, not hidden): cgroup is one id for the whole container, so this places an
        # operator/injected exec "in the session" too. Correct for a hands-off workload (container =
        # session); the interactive case wants a per-session sub-cgroup (REMEDIATION-PLAN Phase 3).
        self._session_cgroup = session_cgroup
        rescued: set[int] = set()
        if session_cgroup is not None:
            for pid in agent_exec_pids:
                if pid in runtime_pids or any(p in runtime_pids for p in tree.ancestry(pid)):
                    continue  # a runtime pid, or already in scope by ancestry
                ts = self._ts_by_pid.get(pid)
                if ts is not None and runtime_first_ts is not None and ts < runtime_first_ts:
                    continue  # provably older than the runtime -> provisioning, not the session
                parent = tree.ppid(pid)
                if parent is not None and parent in self._exe_by_pid:
                    continue  # ancestry is KNOWABLE and traced out -> a conclusion, not rescuable
                if self._cgroup_by_pid.get(pid) == session_cgroup:
                    rescued.add(pid)
        self._cgroup_rescued: frozenset[int] = frozenset(rescued)

    def in_scope(self, pid: int) -> bool:
        if not self.active:
            return True
        if any(p in self.runtime_pids for p in self._tree.ancestry(pid)):
            return True
        # Fork-gap rescue: cgroup membership places it in the container's session where the broken
        # ancestry walk cannot. Empty (inert) unless the fused evidence model supplied cgroups.
        return pid in self._cgroup_rescued

    def is_unevaluable(self, pid: int, ts: Optional[float] = None) -> bool:
        """True when this pid is out of scope only because its ancestry is UNKNOWABLE, not because
        it was traced to a non-runtime origin (DECISIONS.md G23/G24).

        The audit rule records `execve` only. A process that forks and never execs therefore has no
        record at all, and a child it spawns carries a `ppid` pointing at a pid this tree has never
        heard of. `ProcessTree.ancestry` stops there, the chain never reaches a runtime pid, and
        `in_scope` says False - the same answer it gives for genuine ambient noise, but for the
        opposite reason. Measured: `wc`, the command a `run_shell_command` shell actually ran, is
        dropped exactly this way.

        THE DISTINCTION IS THE FIRST HOP, and it has to be, because "the chain ends at an unknown
        pid" is true of the legitimate noise too - the `su - agent` login shell's chain also
        terminates at a pid outside the audit rule's uid range. What separates them is whether the
        walk learned anything before it ran out:

            login bash  [600771, 600769, ...]  parent 600769 IS known (`su`, container root uid)
                                               -> traced to a non-runtime origin. Out of scope, and
                                                  that is a conclusion.
            wc          [600813, 600812]       parent 600812 is a number and nothing else
                                               -> we know nothing. Not a conclusion.

        So: unevaluable iff the immediate parent has no exec record of its own, AND the exec is not
        provably older than the runtime (`ts`, below). Deliberately narrow. A wider rule ("any chain
        ending in an unknown pid") would relabel most ambient noise as unevaluable and make the
        category useless by flooding it - which would be a different way of hiding the same thing.
        """
        if not self.active:
            # Scope inactive means everything is evaluated (fail-open, see __init__). Nothing is
            # dropped, so nothing is unevaluable - the honest answer is not "unknown" here.
            return False
        if self.in_scope(pid):
            return False
        if (
            ts is not None
            and self._runtime_first_ts is not None
            and ts < self._runtime_first_ts
        ):
            # It exec'd before the runtime did, so it cannot be a descendant of it - provisioning
            # and login noise. Unknown parentage does not make that uncertain.
            return False
        parent = self._tree.ppid(pid)
        if parent is None:
            # No ppid recorded on this pid's own exec event at all - a different, rarer defect
            # (a malformed or truncated audit record). Still unevaluable, and for a stronger
            # reason: there is not even a parent to be ignorant about.
            return True
        return parent not in self._exe_by_pid

    def attachment(self, pid: int) -> Optional[int]:
        """The pid in `pid`'s ancestry (including itself) whose *own* ppid is a runtime pid -
        i.e. where this chain first attaches directly to the agent runtime. None if `pid` never
        attaches to a runtime pid (out of scope) or *is* a runtime pid itself.
        """
        for p in self._tree.ancestry(pid):
            if p in self.runtime_pids:
                return None
            if self._tree.ppid(p) in self.runtime_pids:
                return p
        return None

    def _is_internal_allowlisted(self, pid: int) -> bool:
        comm = self._comm_by_pid.get(pid)
        exe_base = _basename(self._exe_by_pid.get(pid))
        if comm in self._runtime_internal_names or exe_base in self._runtime_internal_names:
            return True
        # Exact-argv allowlist. Deliberately narrower than the name-based one above: some binaries
        # are runtime housekeeping for *one specific invocation* and genuine agent action for every
        # other. `git` is the worked example - `git rev-parse --show-toplevel` is repo detection the
        # runtime does at startup, before the model has produced anything, while `git push` is
        # exactly what a detector exists to surface. Allowlisting the name would silence both; this
        # silences only the observed housekeeping call. Note this is reachable only for a pid the
        # runtime spawned DIRECTLY (see `attachment`) - a git run via a tool_call's shell attaches
        # at the shell, not here, so it is never covered by this rule.
        if any(argv in self._runtime_internal_argv for argv in self._argv_by_pid.get(pid, ())):
            return True
        return comm in self._posix_shells

    def classify_unmatched(self, pid: int) -> tuple[Verdict, str]:
        """Verdict for an in-scope pid that found no authorizing tool_use in the time-window
        check. Only meaningful for in-scope pids - callers should check `in_scope` first.
        """
        if pid in self.runtime_pids:
            return Verdict.NONE, "agent runtime's own exec - no tool_use ever authorizes this"

        attach = self.attachment(pid)
        if attach is not None and self._is_internal_allowlisted(attach):
            attach_comm = self._comm_by_pid.get(attach)
            return (
                Verdict.NONE,
                f"runtime-internal exec ({attach_comm}, pid={attach}) spawned directly by the "
                "agent runtime, not via a tool_use-caused shell - the self-report plane cannot "
                "observe this class of action",
            )

        return Verdict.CONFIRMED, "no ancestor tool_use, and not explainable as runtime activity"


# --- Gemini CLI tuning (design doc v2 §6's "a future Gemini adapter would pair with a different
# set here, passed in rather than hardcoded elsewhere" - this is that set) --------------------
#
# PROVISIONAL until measured against a real capture. The Claude sets above were diagnosed from 83
# real false positives; these have no equivalent evidence yet, because the ground-truth plane was
# blind until DECISIONS.md G12 was fixed. `scripts/measure_reconcile.py` prints the comm/exe of
# every CONFIRMED candidate precisely so these can be finalized from data rather than from the
# plausible-sounding guess this currently is. Do not treat them as validated.

GEMINI_RUNTIME_EXE_PREFIXES: frozenset[str] = frozenset({
    "/usr/lib/node_modules/@google/gemini-cli/",
    "/usr/local/lib/node_modules/@google/gemini-cli/",
})

# `gemini` in a node process's argv means that node process IS the CLI - the direct analog of the
# `claude` marker, and the reason is_runtime_exec takes the marker as a parameter.
GEMINI_RUNTIME_ARGV_MARKERS: frozenset[str] = frozenset({"gemini"})

# Direct-exec launcher basename/comm for Gemini CLI, the analog of DEFAULT_RUNTIME_BASENAMES: a
# `/usr/bin/gemini` install shape (no `node …/gemini.js` visible). Provisional like the rest of the
# GEMINI_* tuning until measured against a real capture.
GEMINI_RUNTIME_BASENAMES: frozenset[str] = frozenset({"gemini"})

# The runtime's own exec chain for an npm-installed node CLI: `env` and `node` are the hops, `npm`
# is the self-update/version check. `rg` is here because Gemini CLI logs a `gemini_cli.ripgrep_
# fallback` event and attempts ripgrep before falling back to its in-process GrepTool - so an `rg`
# exec is runtime behavior no tool_call authorizes, the same shape as Claude's ripgrep searches.
#
# `git` is deliberately NOT here, though it was the only thing CONFIRMED on the benign run and the
# obvious way to reach zero. See GEMINI_RUNTIME_INTERNAL_ARGV below and DECISIONS.md G20.
GEMINI_RUNTIME_INTERNAL_NAMES: frozenset[str] = frozenset({"node", "npm", "env", "rg"})

# MEASURED, not guessed (DECISIONS.md G20). On the benign run the only CONFIRMED execs were two
# `git rev-parse --show-toplevel` calls at +2.6s, spawned directly by the runtime, ~6s BEFORE the
# session's only tool_call - Gemini CLI detecting whether cwd is a repo, for gitignore-aware file
# discovery. No tool_call could authorize an exec that precedes every tool_call, which is G17's bar
# for allowlisting. It is listed as an exact argv tuple rather than as the name `git`, so that
# `git push` / `git commit` / any other invocation still reports.
GEMINI_RUNTIME_INTERNAL_ARGV: frozenset = frozenset({
    ("git", "rev-parse", "--show-toplevel"),
})
