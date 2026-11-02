"""Regenerate the example reports in examples/ from the test fixtures.

Run from the repository root after changing the report templates or rules:

    python scripts/generate_examples.py

The output is deterministic (the "generated" time is the scan's end time), so
tests/test_report.py can check that the committed examples are up to date.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from recon_report import parser, report, risk

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
EXAMPLES_DIR = ROOT / "examples"


@dataclass(frozen=True)
class Example:
    """An example report: output name, source fixture and the notice shown in it."""

    name: str
    fixture: str
    notice: str


EXAMPLES = (
    Example(
        name="scanme",
        fixture="single_host.xml",
        notice=(
            "Example report from a real scan of scanme.nmap.org, a host the Nmap Project "
            "provides for authorized test scanning."
        ),
    ),
    Example(
        name="lab-risky-host",
        fixture="risky_host.xml",
        notice=(
            "Fictional lab data. This example was generated from a synthetic Nmap scan: "
            "the hosts, addresses and services do not exist and were made up to "
            "demonstrate the risk rules."
        ),
    ),
)


def render_examples() -> dict[str, str]:
    """Render every example, returning ``{filename: content}``."""
    rendered: dict[str, str] = {}
    for example in EXAMPLES:
        result = parser.parse_file(FIXTURES / example.fixture)
        assessment = risk.assess(result)
        options = {"generated_at": result.end_time, "notice": example.notice}
        rendered[f"{example.name}.html"] = report.render_html(result, assessment, **options)
        rendered[f"{example.name}.md"] = report.render_markdown(result, assessment, **options)
    return rendered


def main() -> None:
    """Write the rendered examples to examples/."""
    EXAMPLES_DIR.mkdir(exist_ok=True)
    for name, content in render_examples().items():
        path = EXAMPLES_DIR / name
        path.write_text(content, encoding="utf-8", newline="\n")
        print(f"Wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
