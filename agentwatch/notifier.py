"""Terminal notifier - quiet when empty (design doc §5): "Quiet when empty."

Formatting is separated from the actual print so it's testable without capturing stdout/stderr.
"""
from __future__ import annotations

import sys
from typing import Iterable, Optional, TextIO

from agentwatch.findings import Finding


def format_notification(findings: Iterable[Finding]) -> Optional[str]:
    """None means "say nothing" - the caller must not print anything in that case."""
    findings = list(findings)
    if not findings:
        return None
    lines = [f"[agentwatch] {len(findings)} new finding(s):"]
    for f in sorted(findings, key=lambda x: x.ts):
        lines.append(f"  - {f.detector:16s} {f.summary}")
    return "\n".join(lines)


def notify(findings: Iterable[Finding], stream: TextIO = sys.stderr) -> bool:
    """Write the notification only if there's something to say. Returns whether it wrote."""
    message = format_notification(findings)
    if message is None:
        return False
    print(message, file=stream)
    return True
