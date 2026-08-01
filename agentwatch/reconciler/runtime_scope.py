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
) -> bool:
    """Does this exec event's *own* process belong to the agent runtime itself?"""
    if exe and any(exe.startswith(prefix) for prefix in runtime_exe_prefixes):
        return True
    if comm == "node" and any("claude" in a for a in args if isinstance(a, str)):
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
    ) -> None:
        self._tree = tree
        self._runtime_internal_names = runtime_internal_names
        self._posix_shells = posix_shells
        self._exe_by_pid: dict[int, Optional[str]] = {}
        self._comm_by_pid: dict[int, Optional[str]] = {}
        runtime_pids: set[int] = set()

        for ev in ground_truth_events:
            if ev.kind != EXEC or ev.pid is None:
                continue
            self._exe_by_pid[ev.pid] = ev.exe
            self._comm_by_pid[ev.pid] = ev.comm
            if ev.uid == agent_uid and is_runtime_exec(ev.exe, ev.comm, ev.args, runtime_exe_prefixes):
                runtime_pids.add(ev.pid)

        self.runtime_pids: frozenset[int] = frozenset(runtime_pids)
        # No runtime pid found at all for this agent_uid -> we can't tell session activity from
        # ambient noise, so scoping fails *open* (evaluate everything, v1's old behavior) rather
        # than silently going blind. See DECISIONS.md - a security detector should never respond
        # to "I couldn't find what I was looking for" by evaluating nothing.
        self.active: bool = bool(runtime_pids)

    def in_scope(self, pid: int) -> bool:
        if not self.active:
            return True
        return any(p in self.runtime_pids for p in self._tree.ancestry(pid))

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
