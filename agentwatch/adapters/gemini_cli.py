"""Gemini CLI telemetry adapter — concatenated OTel objects, NOT line-delimited JSON.

FORMAT (measured against Gemini CLI 0.53.1, `scripts/00-probe-gemini-planes.sh`; see
DECISIONS.md "Gemini adapter" G6 for the full structural dump):

The outfile is named `telemetry.jsonl` and is not JSONL. It is a stream of **concatenated
pretty-printed JSON objects**, multi-line, with no separator — `}{` at the seam. A
`readlines()` + `json.loads` loop yields zero records without erroring, which is exactly the
silent-underextraction failure `reconciler/parse_health.py` exists to catch. Parsing is a
`json.JSONDecoder().raw_decode()` loop over the whole text.

Three object families are interleaved, distinguished structurally, not by a type tag:

    LogRecord  `attributes` + `_body` (+ optional `spanContext`)   — per-event detail
    Metric     `scopeMetrics`                                       — counters, no per-event detail
    Span       `name` + `startTime`/`endTime` + `_spanContext`      — when the call ACTUALLY ran

This list used to call the LogRecord "the useful one" and dismiss Spans as duplicating the
api_request/api_response timing. That was wrong, and it cost the correlation: a `name == "tool_call"`
span is the ONLY record carrying the call's **start** time and `gen_ai.tool.call_id`. The log record
is written at the end of the call, so authorizing from it can never explain the exec the call
caused. Both are read now — one event per call, stamped from the span. DECISIONS.md G23.

Record kind lives at `attributes["event.name"]`: observed values are `gemini_cli.config`,
`gemini_cli.user_prompt`, `gemini_cli.api_request`, `gemini_cli.api_response`,
`gemini_cli.model_routing`, `gemini_cli.startup_stats`, `gemini_cli.ripgrep_fallback`,
`gemini_cli.plan.approval_mode_duration`, `gemini_cli.tool_call`, and
`gen_ai.client.inference.operation.details`.

TIMESTAMPS are `hrTime: [seconds, nanoseconds]`, already Unix epoch — no ISO parsing needed
(`attributes["event.timestamp"]` carries an ISO string as a fallback for records lacking hrTime).

PROMPT-BEARING — WHAT THIS ADAPTER DELIBERATELY DOES NOT READ:
`_body` is the OTel log message and, for prompt-logging records, contains prompt text;
Capsule D8 established that `logPrompts:false` does not scrub it. This adapter therefore
**never reads `_body`** and never populates `NormalizedEvent.text`. `gemini_cli.user_prompt`
carries `prompt_length` (an int) and `prompt_id` (an opaque id), which is everything the
timeline needs and none of the content. Sanitization by construction rather than by scrubbing:
there is no path from prompt text into a `NormalizedEvent`, so no downstream persistence of a
finding can leak it.

TOOL CALLS: PRESENT, BUT NAME-ONLY (§1, settled by step 0b — DECISIONS.md G10):
A run that actually uses a tool emits TWO records for the one call, and both are needed:

    LogRecord `gemini_cli.tool_call`   function_name, tool_type, duration_ms, success, decision
                                       — the outcome. Stamped at the END of the call.
    Span      `name == "tool_call"`    startTime, endTime, gen_ai.tool.name, gen_ai.tool.call_id
                                       — when it ran, and the only per-call id on this plane.

They are paired into ONE `TOOL_USE`, stamped `span_start`. Emitting both would double-count every
call; stamping from the log record alone authorizes nothing (G23). `gen_ai.tool.name` and
`gen_ai.tool.call_id` do NOT appear on the log record — across 7 real records in two captures,
never once — so the adapter reads them only where they exist.

So the plane is strong enough to authorize: `EMITS_TOOL_USE` is True.

What it does **not** carry is the arguments. There is no `function_args`-shaped key path in any
record — the plane says *which tool* ran, never *what it ran on*. Two consequences, and the
difference between them matters:

  - Authorization does not depend on the arguments, and it works — but only because of the span.
    `reconciler/orphan.py` authorizes on the tool_use *timestamp* alone (`_authorizing_tool_use`
    compares only `tu.ts`); it never reads the name or the input. Measured on a real shell-out run
    (DECISIONS.md G23): stamped from the span's `startTime`, the tool_call authorizes the shell it
    spawned 4ms later — `matched` goes 0 -> 1, CONFIRMED 1 -> 0 on the same capture.

    This docstring previously claimed "authorization works completely", reasoned from the fact
    that only `tu.ts` is compared and never checking WHICH END of the call `tu.ts` denoted. It was
    end-stamped, so nothing matched. The claim is true now for a different reason than it was
    originally made.
  - `claimed_action` in the spec's sense — "the command/path the agent says it ran" — is **not
    available** and `tool_input` is therefore not a claim about a command. Evidence of *what* was
    executed exists only in the auditd plane. Anything that later wants to compare claimed-vs-actual
    *commands* (rather than claimed-vs-actual timing) cannot be built on this runtime's telemetry,
    and should say so rather than degrade quietly.

The arguments are plausibly inside `_body`, which is prompt-bearing and deliberately unread (see
below). Recovering them would mean reading the field this adapter exists not to read.

PARSESTATS SEMANTICS DIFFER FROM THE CLAUDE ADAPTER: there are no lines, so `lines_total` counts
**records** and `lines_skipped` counts records that decoded but yielded nothing usable. `skip_rate`
stays meaningful (and is arguably tighter than a line-based rate); anything reading it as a line
count is reading it wrong. `source_line` is a record index, for the same reason.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Iterable, Iterator, Optional

from agentwatch.adapters.base import TranscriptAdapter
from agentwatch.events import MODEL_CALL, PROMPT, TOOL_USE, NormalizedEvent, ParseStats

# Versions this adapter has been validated against. Mirrors claude_code.KNOWN_VERSIONS: recorded
# and fed to parse-health, does not branch parsing.
#
# THIS IS THE OTel INSTRUMENTATION SCHEMA VERSION, NOT THE CLI VERSION - a real and unwelcome
# difference from the Claude adapter, which reads the actual `version` Claude Code stamps on every
# message line. Gemini CLI's telemetry carries **no CLI version anywhere**: a full real capture
# contains only `instrumentationScope.version = "v1"` (17 records) and an empty
# `scopeMetrics[].scope.version` (6). The CLI was 0.53.1 and that string appears nowhere.
#
# So drift-gating is strictly weaker here than for Claude. `v1` will not change when the CLI
# upgrades, only when Google reshapes the telemetry schema - which catches the breaking case
# (fields moved) but not the silent one (same schema, different semantics). Anyone relying on
# parse-health to notice a Gemini upgrade should know it will not. Recorded in DECISIONS.md G21.
#
# It previously read {"0.53.1"}, which was never observed - it came from a synthetic fixture that
# invented the field. The gate therefore fired on 100% of real runs. A health check that always
# fires is one people learn to ignore, and it is the check that would have caught G19.
KNOWN_VERSIONS = frozenset({"v1"})

# event.name values mapped to an emitted event. Anything else decodes fine and is ignored, the
# same way claude_code.py ignores mode/ai-title/attachment lines — not an error, just nothing to
# extract.
_PROMPT_EVENTS = frozenset({"gemini_cli.user_prompt"})
_TOOL_CALL_EVENTS = frozenset({"gemini_cli.tool_call"})
_CALL_EVENTS = frozenset({
    "gemini_cli.api_request",
    "gemini_cli.api_response",
    "gen_ai.client.inference.operation.details",
})

# Token-count attributes copied into tool_input (structured ints, never text).
_TOKEN_KEYS = (
    "input_token_count",
    "output_token_count",
    "cached_content_token_count",
    "thoughts_token_count",
    "tool_token_count",
    "total_token_count",
    "gen_ai.usage.input_tokens",
    "gen_ai.usage.output_tokens",
)


def _ts_from_hrtime(raw: object) -> Optional[float]:
    """`[seconds, nanoseconds]` -> float epoch seconds. None if not that shape."""
    if not isinstance(raw, (list, tuple)) or len(raw) != 2:
        return None
    secs, nanos = raw
    if not isinstance(secs, (int, float)) or not isinstance(nanos, (int, float)):
        return None
    if isinstance(secs, bool) or isinstance(nanos, bool):
        return None
    return float(secs) + float(nanos) / 1e9


def _ts_from_iso(raw: object) -> Optional[float]:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


class _ToolSpan:
    """A `tool_call` Span: the same call the log record describes, but stamped at both ends.

    This is the record family the reconciler actually needs and the adapter used to throw away
    (see the Span note in the module docstring). It carries `startTime`, `endTime`,
    `gen_ai.tool.name` and `gen_ai.tool.call_id` — a real start timestamp and a per-call id.
    """

    __slots__ = ("start", "end", "name", "call_id")

    def __init__(self, start: float, end: float, name: str, call_id: Optional[str]) -> None:
        self.start = start
        self.end = end
        self.name = name
        self.call_id = call_id


# How far a log record may sit from its span's end and still be paired with it. Observed: 2.4ms
# (the record is written immediately after the span closes). 0.5s is deliberately loose, because
# the consequence of pairing too eagerly is bounded - a span is consumed at most once, both belong
# to the same tool name, and the worst case is authorizing from a start time a few hundred ms off.
# The consequence of pairing too tightly is silently falling back to the end-stamped timestamp,
# which is the bug this exists to fix.
_SPAN_PAIRING_TOLERANCE_SECONDS = 0.5


def _tool_spans(text: str) -> list[_ToolSpan]:
    """Collect `tool_call` spans in one pre-pass, so a log record can be paired with its span.

    DELIBERATELY READS ONLY FOUR FIELDS. These spans also carry `gen_ai.tool.description` and
    `gen_ai.agent.description`, and the *inference* spans alongside them carry
    `gen_ai.system_instructions` — content this adapter has no business extracting, on the same
    reasoning that keeps it out of `_body`.
    """
    spans: list[_ToolSpan] = []
    for obj, ok in iter_records(text):
        if not ok:
            break
        if obj is None or obj.get("name") != "tool_call":
            continue
        attributes = obj.get("attributes")
        if not isinstance(attributes, dict):
            continue
        name = attributes.get("gen_ai.tool.name")
        start = _ts_from_hrtime(obj.get("startTime"))
        end = _ts_from_hrtime(obj.get("endTime"))
        if not isinstance(name, str) or not name or start is None or end is None:
            continue
        call_id = attributes.get("gen_ai.tool.call_id")
        spans.append(_ToolSpan(start, end, name, call_id if isinstance(call_id, str) else None))
    return spans


def _take_span(spans: list[_ToolSpan], ts: float, name: str) -> Optional[_ToolSpan]:
    """The unconsumed span for `name` whose end is nearest `ts`. Consumed on return."""
    best: Optional[_ToolSpan] = None
    best_gap = _SPAN_PAIRING_TOLERANCE_SECONDS
    for span in spans:
        if span.name != name:
            continue
        gap = abs(ts - span.end)
        if gap <= best_gap:
            best, best_gap = span, gap
    if best is not None:
        spans.remove(best)
    return best


def iter_records(text: str) -> Iterator[tuple[Optional[dict], bool]]:
    """Stream concatenated JSON objects. Yields `(obj, ok)`; `(None, False)` ends the stream.

    Tolerates leading/trailing whitespace, trailing garbage, and a truncated final record — the
    file is appended live, so reading it mid-write is the normal case, not the exceptional one.
    A truncated tail costs one record, never an exception.
    """
    decoder = json.JSONDecoder()
    index = 0
    length = len(text)
    while index < length:
        remainder = text[index:]
        stripped = remainder.lstrip()
        if not stripped:
            return
        consumed = length - len(stripped)
        try:
            obj, offset = decoder.raw_decode(stripped)
        except ValueError:
            yield None, False
            return
        index = consumed + offset
        yield (obj if isinstance(obj, dict) else None), True


class GeminiCliAdapter(TranscriptAdapter):
    """`(telemetry text) -> [NormalizedEvent]`, defensively. See the module docstring."""

    #: This runtime's self-report plane CAN express a tool call (step 0b, DECISIONS.md G10), so
    #: parse-health's "tool_use craters" check is meaningful here rather than a permanent false
    #: alarm. Kept as an explicit flag because the answer was not obvious and cost two probes to
    #: establish - a future runtime may well answer False, and the caller should ask rather than
    #: assume every adapter can authorize.
    EMITS_TOOL_USE = True

    def __init__(self) -> None:
        self._stats = ParseStats()

    @property
    def stats(self) -> ParseStats:
        return self._stats

    def parse_lines(self, lines: Iterable[str], source_file: str = "") -> Iterator[NormalizedEvent]:
        """Note the interface mismatch: the base class is line-oriented and this format is not.

        The lines are rejoined and decoded as one stream. `parse_file` in the base class still
        works unchanged, which is why the interface is honored rather than widened.
        """
        self._stats = ParseStats()
        text = "".join(lines)
        # Pre-pass: the authorizing timestamp lives in a different record from the tool call's
        # detail, and spans are not guaranteed to precede their log record in file order.
        spans = _tool_spans(text)

        for index, (obj, ok) in enumerate(iter_records(text)):
            if not ok:
                # Truncated or corrupt tail. Counted so parse-health can see it; not an error.
                self._stats.lines_total += 1
                self._stats.record_skip("truncated_or_undecodable_tail")
                return
            self._stats.lines_total += 1
            if obj is None:
                self._stats.record_skip("record_not_a_json_object")
                continue
            yield from self._events_from_record(obj, source_file, index, spans)

    def _events_from_record(
        self, obj: dict, source_file: str, index: int, spans: list
    ) -> Iterator[NormalizedEvent]:
        attributes = obj.get("attributes")
        if not isinstance(attributes, dict):
            # Metric records (`scopeMetrics`) and anything else without attributes. Valid shapes
            # carrying no per-event detail — dropped deliberately, and not counted as a skip, so
            # the skip-rate keeps meaning "records I should have understood and didn't".
            return

        self._stats.record_version(_scope_version(obj))

        event_name = attributes.get("event.name")
        if not isinstance(event_name, str):
            # A Span carries `name` instead; it duplicates the api_request/api_response pair's
            # timing and adds nothing the reconciler uses.
            return

        ts = _ts_from_hrtime(obj.get("hrTime"))
        if ts is None:
            ts = _ts_from_iso(attributes.get("event.timestamp"))
        if ts is None:
            self._stats.record_skip("missing_or_bad_timestamp")
            return

        session_id = attributes.get("session.id")
        prompt_id = attributes.get("prompt_id")
        session_id = session_id if isinstance(session_id, str) else None
        prompt_id = prompt_id if isinstance(prompt_id, str) else None

        if event_name in _PROMPT_EVENTS:
            self._stats.events_emitted += 1
            length = attributes.get("prompt_length")
            yield NormalizedEvent(
                ts=ts,
                kind=PROMPT,
                session_id=session_id,
                uuid=prompt_id,
                # `text` stays empty by design — the prompt itself is in `_body`, which this
                # adapter never reads. Length is metadata; content is not carried at all.
                tool_input={"prompt_length": length} if isinstance(length, int) else {},
                raw_kind=event_name,
                source_file=source_file,
                source_line=index,
            )
            return

        if event_name in _TOOL_CALL_EVENTS:
            # The authorizing event. Name and timestamp are all reconciler/orphan.py needs; the
            # arguments are not in this plane at all (see the module docstring), so tool_input
            # carries identity/provenance rather than a claimed command. It deliberately does not
            # get a `command`-shaped key, so nothing downstream can mistake it for one.
            name = attributes.get("function_name") or attributes.get("gen_ai.tool.name")
            if not isinstance(name, str) or not name:
                self._stats.record_skip("tool_call_without_name")
                return
            detail = {}
            # Re-stamp to the START of the call, from its span. The log record's own timestamp is
            # the end of the call, which cannot authorize the exec the call itself caused - see
            # DECISIONS.md G23, where this was measured as `matched = 0` on a real shell-out.
            # The pairing is internal to one process's own records and fails safe: no span found
            # means the old end-stamped timestamp, i.e. today's behaviour, marked as such.
            span = _take_span(spans, ts, name)
            if span is not None:
                ts = span.start
                detail["stamp"] = "span_start"
                detail["span_end"] = span.end
                if span.call_id:
                    detail["call_id"] = span.call_id
            else:
                # Not an error: spans are a separate OTel export and a logs-only configuration is
                # legitimate. But an authorization built on this timestamp is unreliable in the one
                # direction that matters, so it says so rather than looking identical to a good one.
                detail["stamp"] = "record_end_no_span"
            # NOT read from this record: `gen_ai.tool.call_id` / `gen_ai.tool.name`. The adapter
            # used to look for both here, and the synthetic fixture supplied them - but across 7
            # real tool_call log records in two captures, neither has ever appeared. They exist
            # only on the span (read above). Removed rather than left as a harmless fallback,
            # because a read of a field that is never present documents a plane that does not
            # exist; `function_name` is the real one. Third instance of DECISIONS.md G21.
            tool_type = attributes.get("tool_type")
            if isinstance(tool_type, str) and tool_type:
                detail["tool_type"] = tool_type
            # `duration_ms` is carried because THE RECORD IS STAMPED AT COMPLETION, not at the
            # start of the call: in every real capture the tool_call record lands ~14ms after the
            # api_response that requested it, with a duration of 8-9ms in between. So `ts` is the
            # END of the tool's execution, and the interval in which anything the tool spawned
            # actually ran is [ts - duration_ms/1000, ts] - entirely BEFORE `ts`.
            #
            # That matters to the reconciler, whose window is forward-only ([tu.ts, tu.ts+window]),
            # and it is not recoverable from any other field. A non-prompt-bearing float, same
            # class as the token counts below.
            duration = attributes.get("duration_ms")
            if isinstance(duration, (int, float)) and not isinstance(duration, bool):
                detail["duration_ms"] = float(duration)
            success = attributes.get("success")
            if isinstance(success, bool):
                detail["success"] = success
            self._stats.events_emitted += 1
            yield NormalizedEvent(
                ts=ts,
                kind=TOOL_USE,
                session_id=session_id,
                uuid=prompt_id,
                tool_name=name,
                tool_input=detail,
                raw_kind=event_name,
                source_file=source_file,
                source_line=index,
            )
            return

        if event_name in _CALL_EVENTS:
            self._stats.events_emitted += 1
            detail: dict = {}
            model = attributes.get("model") or attributes.get("gen_ai.request.model")
            if isinstance(model, str) and model:
                detail["model"] = model
            for key in _TOKEN_KEYS:
                value = attributes.get(key)
                if isinstance(value, int) and not isinstance(value, bool):
                    detail[key] = value
            status = attributes.get("status_code") or attributes.get("http.status_code")
            if isinstance(status, int) and not isinstance(status, bool):
                detail["status_code"] = status
            yield NormalizedEvent(
                ts=ts,
                kind=MODEL_CALL,
                session_id=session_id,
                uuid=prompt_id,
                tool_input=detail,
                raw_kind=event_name,
                source_file=source_file,
                source_line=index,
            )
            return

        # Known-but-uninteresting kinds (config, startup_stats, model_routing, ripgrep_fallback,
        # plan.approval_mode_duration). Valid records with nothing the reconciler consumes.


def _scope_version(obj: dict) -> Optional[str]:
    scope = obj.get("instrumentationScope")
    if isinstance(scope, dict):
        version = scope.get("version")
        if isinstance(version, str) and version:
            return version
    return None
