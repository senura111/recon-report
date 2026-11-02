"""Render HTML and Markdown findings reports.

Not implemented yet.
"""

from __future__ import annotations

from pathlib import Path


def render_html(findings: object, output_path: Path) -> Path:
    """Render findings as an HTML report.

    Raises:
        NotImplementedError: Always, until reporting is implemented.
    """
    raise NotImplementedError("HTML reports are not implemented yet")


def render_markdown(findings: object, output_path: Path) -> Path:
    """Render findings as a Markdown report.

    Raises:
        NotImplementedError: Always, until reporting is implemented.
    """
    raise NotImplementedError("Markdown reports are not implemented yet")
