"""Regenerate the screenshots in docs/images/ used by the README.

Run from the repository root after changing the findings output, rules or
report templates:

    python scripts/generate_screenshots.py              # terminal SVG only
    python scripts/generate_screenshots.py --report-png  # also the report PNGs

The terminal screenshot (findings-terminal.svg) is a recording of the
``findings`` command on the scanme fixture, made with rich's
``Console(record=True)``.

``--report-png`` captures report-top.png and report-findings.png from
examples/lab-risky-host.html with headless Microsoft Edge or Chrome, so
regenerate the examples first (scripts/generate_examples.py).
"""

from __future__ import annotations

import argparse
import html
import io
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from rich.console import Console
from rich.text import Text

from recon_report import cli, parser, risk

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "single_host.xml"
REPORT = ROOT / "examples" / "lab-risky-host.html"
IMAGES_DIR = ROOT / "docs" / "images"
TERMINAL_SVG = IMAGES_DIR / "findings-terminal.svg"

# The XML path the fixture's own scan wrote, so the prompt matches real usage.
COMMAND = "recon-report findings scans/scan_scanme.nmap.org_20261102T180912Z.xml"
TERMINAL_WIDTH = 80

# Output file and the report fragment to scroll to.
REPORT_SHOTS = (("report-top.png", ""), ("report-findings.png", "#findings"))
VIEWPORT = (1280, 900)
BROWSER_TIMEOUT_SECONDS = 60

# Headless Chromium paints a blank screenshot when the page itself scrolls to a
# fragment, so the report is loaded in a viewport-sized iframe that scrolls instead.
FRAME_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
html, body {{ margin: 0; background: #0d1117; }}
iframe {{ display: block; border: 0; width: {width}px; height: {height}px; }}
</style></head>
<body><iframe src="{src}"></iframe></body></html>
"""


def render_findings_svg() -> str:
    """Render the ``findings`` output for the scanme fixture as an SVG terminal image."""
    console = Console(
        record=True,
        width=TERMINAL_WIDTH,
        force_terminal=True,
        color_system="truecolor",
        file=io.StringIO(),  # Record only; do not echo to stdout.
    )
    console.print(Text.assemble(("$ ", "bold green"), COMMAND))
    cli._print_findings(risk.assess(parser.parse_file(FIXTURE)), console)
    return console.export_svg(title="recon-report findings")


def find_browser() -> str | None:
    """Return the path of Microsoft Edge or Chrome, or ``None`` if neither is found."""
    for env in ("ProgramFiles(x86)", "ProgramFiles"):
        base = os.environ.get(env)
        if base:
            edge = Path(base) / "Microsoft" / "Edge" / "Application" / "msedge.exe"
            if edge.is_file():
                return str(edge)
    for name in ("msedge", "microsoft-edge", "google-chrome", "chromium", "chrome"):
        path = shutil.which(name)
        if path:
            return path
    return None


def capture_report_pngs(browser: str) -> None:
    """Screenshot the example report with a headless browser into docs/images/."""
    width, height = VIEWPORT
    with tempfile.TemporaryDirectory() as tmp:
        frame = Path(tmp) / "frame.html"
        for name, fragment in REPORT_SHOTS:
            src = html.escape(REPORT.as_uri() + fragment)
            frame.write_text(
                FRAME_PAGE.format(width=width, height=height, src=src), encoding="utf-8"
            )
            output = IMAGES_DIR / name
            args = [
                browser,
                "--headless",
                "--disable-gpu",
                "--hide-scrollbars",
                f"--user-data-dir={Path(tmp) / 'profile'}",
                f"--window-size={width},{height}",
                "--virtual-time-budget=3000",
                f"--screenshot={output}",
                frame.as_uri(),
            ]
            subprocess.run(args, check=True, capture_output=True, timeout=BROWSER_TIMEOUT_SECONDS)
            print(f"Wrote {output.relative_to(ROOT)}")


def main() -> None:
    """Write the screenshots to docs/images/."""
    arg_parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    arg_parser.add_argument(
        "--report-png",
        action="store_true",
        help="also capture the HTML report screenshots with headless Edge or Chrome",
    )
    options = arg_parser.parse_args()

    IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    TERMINAL_SVG.write_text(render_findings_svg(), encoding="utf-8", newline="\n")
    print(f"Wrote {TERMINAL_SVG.relative_to(ROOT)}")

    if options.report_png:
        browser = find_browser()
        if browser is None:
            sys.exit("Microsoft Edge or Chrome not found; cannot capture the report PNGs.")
        capture_report_pngs(browser)


if __name__ == "__main__":
    main()
