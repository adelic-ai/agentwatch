"""Claude Code `.jsonl` transcript adapter.

Per sample-telemetry/README.md: the schema DRIFTS across Claude Code versions (fields get
added/renamed roughly per release). This adapter keys off only the stable core documented there:

    - each line is a JSON object
    - there is a `type` (and, on message-bearing lines, `message.role`)
    - `message.content` is a list of blocks, each with a `type` in
      {text, thinking, tool_use, tool_result}
    - a `tool_use` block has `name` + `input`
    - a timestamp exists (top-level `timestamp`, ISO-8601, on message-bearing lines)

Everything else is read with `.get()` and ignored if absent. Unrecognized top-level `type`s
(observed in a live transcript: mode, permission-mode, file-history-snapshot, ai-title,
last-prompt, attachment - none of which carry reasoning/tool_use content) are skipped, not
treated as errors - only lines that fail to parse as JSON, or that don't match the stable core
well enough to extract an event, count as a "skip" in ParseStats.

Drift-gating (v2, design doc v2 §4): schema drift across Claude Code versions is exactly what
makes this adapter's `.get()`-everywhere defensiveness necessary in the first place, and exactly
what can silently make it extract *less* without erroring - a renamed `content` key wouldn't raise,
it would just make every line look like the "nothing to extract" case. `KNOWN_VERSIONS` below is
the "small per-version field map" the design doc asks for: right now it has exactly one entry (the
only version this build has real transcript data for - see the contract test in
tests/test_claude_code_adapter.py, which pins this adapter's extraction against the real
fixtures/transcript.jsonl). A version not in this set doesn't change parsing (there's no second
version's field names to switch on yet - inventing a second, untested code path would be worse
than not having one), but it's recorded (`ParseStats.versions_seen`) and feeds
reconciler/parse_health.py's "unknown version" signal - the actual safety net is the skip-rate and
tool_use-vs-exec sanity checks there, not this registry by itself.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable, Iterator, Optional

from agentwatch.adapters.base import TranscriptAdapter
from agentwatch.events import REASONING, TOOL_USE, NormalizedEvent, ParseStats

# type values that carry a message.content we might care about
_MESSAGE_TYPES = {"assistant", "user"}

# Claude Code versions this adapter has been validated against a real transcript fixture for
# (design doc v2 §4's "contract tests: one real transcript fixture per known version"). See the
# module docstring above for why this doesn't branch parsing behavior yet.
KNOWN_VERSIONS = frozenset({"2.1.220"})


def _parse_ts(raw: object) -> Optional[float]:
    """ISO-8601 (with trailing 'Z') -> Unix epoch seconds. None if unparseable/absent."""
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


class ClaudeCodeAdapter(TranscriptAdapter):
    def __init__(self) -> None:
        self._stats = ParseStats()

    @property
    def stats(self) -> ParseStats:
        return self._stats

    def parse_lines(self, lines: Iterable[str], source_file: str = "") -> Iterator[NormalizedEvent]:
        self._stats = ParseStats()
        for lineno, raw_line in enumerate(lines, start=1):
            self._stats.lines_total += 1
            line = raw_line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                self._stats.record_skip("json_decode_error")
                continue
            if not isinstance(obj, dict):
                self._stats.record_skip("not_a_json_object")
                continue

            yield from self._events_from_record(obj, source_file, lineno)

    def _events_from_record(self, obj: dict, source_file: str, lineno: int) -> Iterator[NormalizedEvent]:
        record_type = obj.get("type")
        if record_type not in _MESSAGE_TYPES:
            # Not an error: mode/permission-mode/file-history-snapshot/ai-title/last-prompt/
            # attachment/summary lines carry no reasoning or tool_use content in any observed
            # version. Fail-soft means "skip silently", not "skip loudly" - only count it if we
            # expected content and didn't find a usable shape.
            return

        self._stats.record_version(obj.get("version"))

        message = obj.get("message")
        if not isinstance(message, dict):
            self._stats.record_skip("message_not_dict")
            return

        role = message.get("role")
        content = message.get("content")
        session_id = obj.get("sessionId") or obj.get("session_id")
        uuid = obj.get("uuid")
        parent_uuid = obj.get("parentUuid")
        ts = _parse_ts(obj.get("timestamp"))
        if ts is None:
            self._stats.record_skip("missing_or_bad_timestamp")
            return

        if isinstance(content, str):
            # Bare-string content (common on human turns) carries no tool_use/thinking - nothing
            # for the reconciler/divergence detector to key off. Not a skip: it's a valid,
            # uninteresting shape.
            self._stats.events_emitted += 0
            return

        if not isinstance(content, list):
            self._stats.record_skip("content_not_list_or_str")
            return

        emitted_any = False
        for block in content:
            if not isinstance(block, dict):
                continue
            block_type = block.get("type")

            if block_type == "tool_use" and role == "assistant":
                name = block.get("name")
                if not name:
                    continue
                emitted_any = True
                self._stats.events_emitted += 1
                yield NormalizedEvent(
                    ts=ts,
                    kind=TOOL_USE,
                    session_id=session_id,
                    uuid=uuid,
                    parent_uuid=parent_uuid,
                    tool_name=name,
                    tool_input=block.get("input") if isinstance(block.get("input"), dict) else {},
                    raw_kind=block_type,
                    source_file=source_file,
                    source_line=lineno,
                )

            elif block_type in ("thinking", "text") and role == "assistant":
                text = block.get(block_type) if block_type == "thinking" else block.get("text")
                if not isinstance(text, str) or not text.strip():
                    continue
                emitted_any = True
                self._stats.events_emitted += 1
                yield NormalizedEvent(
                    ts=ts,
                    kind=REASONING,
                    session_id=session_id,
                    uuid=uuid,
                    parent_uuid=parent_uuid,
                    text=text,
                    raw_kind=block_type,
                    source_file=source_file,
                    source_line=lineno,
                )

            # tool_result and anything else: not reasoning or claimed action, out of scope for
            # the reconciler/divergence detector - intentionally dropped, not a skip.

        if not emitted_any:
            # A message-bearing line with a content list but nothing we extract from it (e.g. an
            # all-tool_result user turn). Valid shape, just nothing to yield.
            pass
