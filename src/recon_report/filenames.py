"""Build filesystem-safe, timestamped names for scan and report output files."""

from __future__ import annotations

import re
from datetime import datetime, timezone

MAX_PART_LENGTH = 64
"""Longest filename part :func:`safe_part` returns, so names stay well under OS limits."""

_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]")


def safe_part(value: str) -> str:
    """Replace characters other than ``A-Z a-z 0-9 . _ -`` with ``_`` and cap the length.

    Values may come from untrusted scan data (e.g. hostnames), so separators,
    drive letters and other special characters are never passed through.
    """
    return _UNSAFE_CHARS.sub("_", value)[:MAX_PART_LENGTH]


def timestamp(now: datetime | None = None) -> str:
    """Return a compact UTC timestamp such as ``20261102T093015Z``."""
    return (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
