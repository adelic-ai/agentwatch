"""Structural probe for Gemini CLI's telemetry outfile. TYPES AND KEY PATHS ONLY.

Runs *inside* the capsule container, against /home/agent/.gemini/telemetry.jsonl. That file is
prompt-bearing (Capsule D8: prompts reach it even when no API call happens, and logPrompts:false
does not scrub them), so this probe is built so that **no string value can leave the container**:

  - dict keys are printed (structure, not content)
  - value TYPES are printed, plus str/list LENGTHS (size, not content)
  - string VALUES are never printed, with exactly one narrow exception: a discriminator read from
    a known event-name key, and only if it matches an identifier-safe pattern. Anything else is
    reported as <suppressed>.

That exception exists because §3's mapping needs to know which record kinds exist. It is guarded
rather than trusted.

NOTE ON THE SPEC'S INLINE PROBE: GEMINI-ADAPTER-SPEC.md §1 sketches a version whose "kinds" pass
does `k = obj.get("body") or ...` then prints `str(k)[:60]`. In OTel LogRecords `body` is the log
message — for a prompt-logging record that is prompt text, so that line would print up to 60
characters of prompt into output meant to be pasted into a repo. Same intent, leaky in the one
place it mattered. Fixed here.

Output of this script is structural and safe to commit.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter

PATH = sys.argv[1] if len(sys.argv) > 1 else "/home/agent/.gemini/telemetry.jsonl"
SHAPE_RECORDS = 4

# Keys whose value may be printed *if* it is identifier-shaped. Chosen because OTel/Gemini use
# them as record discriminators; none of them is a free-text field.
DISCRIMINATOR_KEYS = ("event.name", "event_name", "name", "gen_ai.operation.name")
IDENTIFIER_SAFE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

# Key-path segments that would mean "this record describes a tool/command execution" — the
# make-or-break question in §1.
TOOL_HINTS = ("tool", "function", "command", "cmd", "exec", "args", "argv", "shell", "call")


def safe_discriminator(obj):
    """An identifier-like record kind, or None. Never returns free text."""
    for key in DISCRIMINATOR_KEYS:
        val = obj.get(key)
        if val is None and isinstance(obj.get("attributes"), dict):
            val = obj["attributes"].get(key)
        if isinstance(val, str):
            return val if IDENTIFIER_SAFE.match(val) else "<suppressed:non-identifier>"
    return None


def describe(value):
    """Type + size. Never the value itself."""
    if isinstance(value, str):
        return f"str(len={len(value)})"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return type(value).__name__
    if value is None:
        return "null"
    return type(value).__name__


def walk(obj, prefix, out):
    """Collect key_path -> type description. Recurses dicts and the first element of lists."""
    if isinstance(obj, dict):
        for key, val in obj.items():
            walk(val, f"{prefix}.{key}" if prefix else key, out)
    elif isinstance(obj, list):
        out.append((f"{prefix}[]", f"list(len={len(obj)})"))
        if obj:
            walk(obj[0], f"{prefix}[]", out)
    else:
        out.append((prefix, describe(obj)))


def records(raw):
    """Stream concatenated JSON objects. THIS LOOP IS THE PARSER (§2) — same shape as the adapter.

    Tolerates: leading/trailing whitespace, trailing garbage, and a truncated final record (the
    file is appended live). Yields (obj, ok); a decode failure ends the stream and is counted.
    """
    dec = json.JSONDecoder()
    i = 0
    while i < len(raw):
        stripped = raw[i:].lstrip()
        if not stripped:
            return
        consumed = len(raw) - len(stripped)
        try:
            obj, off = dec.raw_decode(stripped)
        except ValueError:
            yield None, False
            return
        i = consumed + off
        yield obj, True


def main():
    try:
        with open(PATH, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError as exc:
        print(f"CANNOT READ {PATH}: {exc}")
        return 1

    print(f"file: {PATH}")
    print(f"bytes: {len(raw)}")
    print(f"non-empty lines: {sum(1 for line in raw.splitlines() if line.strip())}")
    print("(line count is meaningless for this format — it is concatenated JSON, not JSONL)")

    total = 0
    failures = 0
    path_types = {}
    path_counts = Counter()
    kinds = Counter()
    top_signatures = Counter()
    shapes_printed = 0

    for obj, ok in records(raw):
        if not ok:
            failures += 1
            break
        total += 1
        if not isinstance(obj, dict):
            continue

        top_signatures[tuple(sorted(obj.keys()))] += 1
        kinds[safe_discriminator(obj) or "<no-discriminator-key>"] += 1

        pairs = []
        walk(obj, "", pairs)
        for path, typedesc in pairs:
            path_counts[path] += 1
            path_types.setdefault(path, set()).add(typedesc.split("(")[0])

        if shapes_printed < SHAPE_RECORDS:
            print(f"\n=== record {shapes_printed} — key paths and types ===")
            for path, typedesc in pairs:
                print(f"  {path}: {typedesc}")
            shapes_printed += 1

    print("\n=== parse summary ===")
    print(f"records decoded : {total}")
    print(f"decode failures : {failures}  (a truncated final record is expected on a live file)")

    print("\n=== distinct record kinds (identifier-safe discriminators only) ===")
    for kind, count in kinds.most_common():
        print(f"  {count:6d}  {kind}")

    print("\n=== distinct top-level key signatures ===")
    for sig, count in top_signatures.most_common(10):
        print(f"  {count:6d}  {list(sig)}")

    print("\n=== full key-path inventory (path -> types, count) ===")
    for path in sorted(path_counts):
        types = ",".join(sorted(path_types[path]))
        print(f"  {path_counts[path]:6d}  {path}: {types}")

    print("\n=== THE MAKE-OR-BREAK QUESTION (§1): tool-call detail present? ===")
    hits = [p for p in sorted(path_counts) if any(h in p.lower() for h in TOOL_HINTS)]
    if hits:
        print("  Key paths suggesting per-tool-call detail:")
        for path in hits:
            print(f"    {path_counts[path]:6d}  {path}: {','.join(sorted(path_types[path]))}")
        print("  => self-report plane MAY be strong. Confirm these carry the command, not just a")
        print("     tool name/count, before populating claimed_action.")
    else:
        print("  NONE. No tool/function/command/args-shaped key path in any record.")
        print("  => self-report plane is CONVERSATION-ONLY. claimed_action stays null (§3), most")
        print("     execs will land in NONE, and the network plane carries more of the weight.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
