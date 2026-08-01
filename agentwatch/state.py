"""Small persisted JSON state - currently just the self-mod baseline hashes (detectors/self_mod.py
is inherently stateful; see DECISIONS.md). Kept separate from findings.jsonl since it's detector
bookkeeping, not something a human should ever need to read.
"""
from __future__ import annotations

import json
from pathlib import Path


def load_state(path) -> dict:
    p = Path(path)
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(path, state: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
