"""Tests for the recon-report CLI. nmap is never executed."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from recon_report import __version__, scanner
from recon_report.cli import app

FIXTURES = Path(__file__).parent / "fixtures"

# A wide terminal keeps rich from wrapping table cells mid-value.
runner = CliRunner(env={"COLUMNS": "200"})


def _fake_run_scan(fixture: str, calls: list[dict] | None = None):
    """Return a run_scan replacement that copies ``fixture`` into the output dir."""

    def fake(target: str, output_dir: Path, ports: str | None, timeout: float) -> Path:
        if calls is not None:
            calls.append(
                {"target": target, "output_dir": output_dir, "ports": ports, "timeout": timeout}
            )
        output_dir.mkdir(parents=True, exist_ok=True)
        return Path(shutil.copy(FIXTURES / fixture, output_dir / "scan.xml"))

    return fake


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_scan_help_lists_options() -> None:
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    for option in ("--output", "--ports", "--timeout"):
        assert option in result.output


# --- scan -----------------------------------------------------------------------


def test_scan_passes_options_and_prints_summary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[dict] = []
    monkeypatch.setattr(scanner, "run_scan", _fake_run_scan("single_host.xml", calls))
    result = runner.invoke(
        app,
        ["scan", "scanme.nmap.org", "--output", str(tmp_path), "--ports", "22,80", "-t", "60"],
    )

    assert result.exit_code == 0, result.output
    assert calls == [
        {"target": "scanme.nmap.org", "output_dir": tmp_path, "ports": "22,80", "timeout": 60.0}
    ]
    saved_line = f"XML saved to {tmp_path / 'scan.xml'}"
    assert saved_line in result.output
    assert result.output.index(saved_line) < result.output.index("Hosts and open ports")
    assert "22/tcp" in result.output
    assert "80/tcp" in result.output


def test_scan_with_unparseable_output_exits_1(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(scanner, "run_scan", _fake_run_scan("malformed.xml"))
    result = runner.invoke(app, ["scan", "10.0.0.5", "--output", str(tmp_path)])
    assert result.exit_code == 1
    assert "XML saved to" in result.output
    assert "not well-formed XML" in result.output


def test_scan_invalid_target_exits_2(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(scanner.shutil, "which", lambda name: "/usr/bin/nmap")
    result = runner.invoke(app, ["scan", "10.0.0.0/24", "--output", str(tmp_path)])
    assert result.exit_code == 2
    assert "Invalid target" in result.output


def test_scan_missing_nmap_exits_1(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(scanner.shutil, "which", lambda name: None)
    result = runner.invoke(app, ["scan", "10.0.0.5", "--output", str(tmp_path)])
    assert result.exit_code == 1
    assert "nmap was not found" in result.output


# --- parse ----------------------------------------------------------------------


def test_parse_single_host() -> None:
    result = runner.invoke(app, ["parse", str(FIXTURES / "single_host.xml")])

    assert result.exit_code == 0, result.output
    assert "Nmap 7.993, started 2026-11-02 18:09:13 UTC, took 11s, 1/1 hosts up" in result.output
    assert "45.33.32.156" in result.output
    assert "scanme.nmap.org" in result.output
    assert "22/tcp" in result.output
    assert "OpenSSH" in result.output
    assert "Apache httpd 2.4.7 ((Ubuntu))" in result.output


def test_parse_multi_host_shows_only_open_ports_and_down_hosts() -> None:
    result = runner.invoke(app, ["parse", str(FIXTURES / "multi_host.xml")])

    assert result.exit_code == 0, result.output
    assert "2/3 hosts up" in result.output
    for expected in ("21/tcp", "22/tcp", "80/tcp", "135/tcp", "445/tcp", "192.168.56.103", "down"):
        assert expected in result.output
    for hidden in ("23/tcp", "3306/tcp", "997", "993"):
        assert hidden not in result.output


def test_parse_host_with_no_open_ports(tmp_path: Path) -> None:
    xml = tmp_path / "closed.xml"
    xml.write_text(
        '<nmaprun version="7.95"><host><status state="up"/>'
        '<address addr="10.0.0.5" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="22"><state state="closed"/></port>'
        "</ports></host></nmaprun>",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["parse", str(xml)])
    assert result.exit_code == 0, result.output
    assert "no open ports" in result.output
    assert "22/tcp" not in result.output


def test_parse_port_without_service_or_product(tmp_path: Path) -> None:
    xml = tmp_path / "bare.xml"
    xml.write_text(
        '<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="49999"><state state="open"/></port>'
        '<port protocol="tcp" portid="8443"><state state="open"/>'
        '<service name="https-alt" extrainfo="TLS"/></port>'
        "</ports></host></nmaprun>",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["parse", str(xml)])
    assert result.exit_code == 0, result.output
    assert "Nmap unknown version, 1/1 hosts up" in result.output
    assert "unknown" in result.output
    assert "(TLS)" in result.output


def test_parse_does_not_render_markup_from_xml(tmp_path: Path) -> None:
    xml = tmp_path / "markup.xml"
    xml.write_text(
        '<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http" product="[bold]evil[/bold]"/></port>'
        "</ports></host></nmaprun>",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["parse", str(xml)])
    assert result.exit_code == 0, result.output
    assert "[bold]evil[/bold]" in result.output


def test_parse_scan_without_hosts() -> None:
    result = runner.invoke(app, ["parse", str(FIXTURES / "minimal.xml")])
    assert result.exit_code == 0, result.output
    assert "0/0 hosts up" in result.output
    assert "No hosts found in scan." in result.output


@pytest.mark.parametrize(
    ("fixture", "message"),
    [
        ("malformed.xml", "not well-formed XML"),
        ("not_nmap.xml", "not Nmap XML"),
        ("xxe.xml", "unsafe XML"),
    ],
)
def test_parse_bad_file_exits_1(fixture: str, message: str) -> None:
    result = runner.invoke(app, ["parse", str(FIXTURES / fixture)])
    assert result.exit_code == 1
    assert message in result.output


def test_parse_missing_file_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(app, ["parse", str(tmp_path / "nope.xml")])
    assert result.exit_code == 2


# --- findings -------------------------------------------------------------------


def test_findings_help_lists_fail_on() -> None:
    result = runner.invoke(app, ["findings", "--help"])
    assert result.exit_code == 0
    assert "--fail-on" in result.output


def test_findings_real_scanme_scan() -> None:
    result = runner.invoke(app, ["findings", str(FIXTURES / "single_host.xml")])
    assert result.exit_code == 0, result.output
    assert "Findings: 0 Critical, 0 High, 1 Medium, 1 Low, 0 Info (2 total)" in result.output
    assert "RR-VER-OPENSSH-OUTDATED" in result.output
    assert "RR-CLEARTEXT-HTTP" in result.output
    assert "scanme.nmap.org" in result.output
    assert result.output.index("RR-VER-OPENSSH-OUTDATED") < result.output.index("RR-CLEARTEXT-HTTP")


def test_findings_table_sorted_by_severity() -> None:
    result = runner.invoke(app, ["findings", str(FIXTURES / "risky_host.xml")])
    assert result.exit_code == 0, result.output
    summary, table = result.output.split("\n", 1)
    assert summary == "Findings: 1 Critical, 6 High, 2 Medium, 1 Low, 0 Info (10 total)"
    # The first cell of each finding row is its severity; read them in table order.
    row_severities = re.findall(r"^\W (Critical|High|Medium|Low|Info) ", table, re.MULTILINE)
    assert row_severities == ["Critical"] + ["High"] * 6 + ["Medium"] * 2 + ["Low"]


def test_findings_without_findings() -> None:
    result = runner.invoke(app, ["findings", str(FIXTURES / "minimal.xml"), "--fail-on", "info"])
    assert result.exit_code == 0, result.output
    assert "(0 total)" in result.output
    assert "No findings." in result.output


@pytest.mark.parametrize(
    ("threshold", "exit_code"),
    [
        ("critical", 0),
        ("high", 0),
        ("medium", 3),
        ("Medium", 3),
        ("LOW", 3),
        ("info", 3),
    ],
)
def test_findings_fail_on(threshold: str, exit_code: int) -> None:
    result = runner.invoke(
        app, ["findings", str(FIXTURES / "single_host.xml"), "--fail-on", threshold]
    )
    assert result.exit_code == exit_code, result.output
    # The findings are printed whether or not the threshold is met.
    assert "RR-VER-OPENSSH-OUTDATED" in result.output
    if exit_code == 3:
        assert "at or above" in result.output


def test_findings_fail_on_critical_finding() -> None:
    result = runner.invoke(
        app, ["findings", str(FIXTURES / "risky_host.xml"), "--fail-on", "critical"]
    )
    assert result.exit_code == 3
    assert "Failing: 1 finding(s) at or above Critical." in result.output


def test_findings_invalid_fail_on_exits_2() -> None:
    result = runner.invoke(
        app, ["findings", str(FIXTURES / "single_host.xml"), "--fail-on", "severe"]
    )
    assert result.exit_code == 2
    assert "Unknown severity" in result.output


def test_findings_bad_file_exits_1() -> None:
    result = runner.invoke(app, ["findings", str(FIXTURES / "malformed.xml")])
    assert result.exit_code == 1
    assert "not well-formed XML" in result.output


def test_findings_does_not_render_markup_from_xml(tmp_path: Path) -> None:
    xml = tmp_path / "markup.xml"
    xml.write_text(
        '<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>'
        '<hostnames><hostname name="[red]host[/red]"/></hostnames><ports>'
        '<port protocol="tcp" portid="23"><state state="open"/>'
        '<service name="telnet" product="[bold]evil[/bold]"/></port>'
        "</ports></host></nmaprun>",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["findings", str(xml)])
    assert result.exit_code == 0, result.output
    assert "[bold]evil[/bold]" in result.output
    assert "[red]host[/red]" in result.output


# --- report ---------------------------------------------------------------------

_REPORT_LINE = re.compile(r"^Report written to (.+)$", re.MULTILINE)


def _written(output: str) -> list[Path]:
    return [Path(path) for path in _REPORT_LINE.findall(output)]


def test_report_help_lists_options() -> None:
    result = runner.invoke(app, ["report", "--help"])
    assert result.exit_code == 0
    for option in ("--format", "--output", "html", "md", "both"):
        assert option in result.output


def test_report_defaults_to_html_in_reports_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["report", str(FIXTURES / "single_host.xml")])

    assert result.exit_code == 0, result.output
    [path] = _written(result.output)
    assert path.parent == Path("reports")
    assert re.fullmatch(r"report_scanme\.nmap\.org_\d{8}T\d{6}Z\.html", path.name)
    assert "Outdated OpenSSH version" in (tmp_path / path).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("fmt", "suffixes"), [("html", [".html"]), ("md", [".md"]), ("both", [".html", ".md"])]
)
def test_report_formats(fmt: str, suffixes: list[str], tmp_path: Path) -> None:
    xml = str(FIXTURES / "risky_host.xml")
    result = runner.invoke(app, ["report", xml, "--format", fmt, "--output", str(tmp_path)])

    assert result.exit_code == 0, result.output
    paths = _written(result.output)
    assert [path.suffix for path in paths] == suffixes
    assert sorted(tmp_path.iterdir()) == sorted(paths)
    for path in paths:
        assert path.name.startswith("report_3-hosts_")
        assert "Docker Engine API exposed without TLS" in path.read_text(encoding="utf-8")


def test_report_without_findings(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["report", str(FIXTURES / "minimal.xml"), "-f", "md", "-o", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    [path] = _written(result.output)
    assert path.name.startswith("report_no-hosts_")
    assert "No findings." in path.read_text(encoding="utf-8")


def test_report_invalid_format_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["report", str(FIXTURES / "single_host.xml"), "--format", "pdf", "-o", str(tmp_path)]
    )
    assert result.exit_code == 2
    assert not list(tmp_path.iterdir())


def test_report_bad_file_exits_1(tmp_path: Path) -> None:
    result = runner.invoke(app, ["report", str(FIXTURES / "malformed.xml"), "-o", str(tmp_path)])
    assert result.exit_code == 1
    assert "not well-formed XML" in result.output
    assert not list(tmp_path.iterdir())


def test_report_unwritable_output_exits_1(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("not a directory", encoding="utf-8")
    result = runner.invoke(
        app, ["report", str(FIXTURES / "single_host.xml"), "-o", str(blocker / "reports")]
    )
    assert result.exit_code == 1
    assert "Cannot write report" in result.output


def test_scan_help_lists_report_options() -> None:
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    for option in ("--report", "--report-dir"):
        assert option in result.output


def test_scan_writes_report(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(scanner, "run_scan", _fake_run_scan("single_host.xml"))
    report_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "scan",
            "scanme.nmap.org",
            "--output",
            str(tmp_path / "scans"),
            "--report",
            "both",
            "--report-dir",
            str(report_dir),
        ],
    )

    assert result.exit_code == 0, result.output
    paths = _written(result.output)
    assert [path.suffix for path in paths] == [".html", ".md"]
    assert all(path.parent == report_dir and path.is_file() for path in paths)
    # The report is written after the scan summary.
    assert result.output.index("Hosts and open ports") < result.output.index("Report written")


def test_scan_without_report_option_writes_no_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(scanner, "run_scan", _fake_run_scan("single_host.xml"))
    result = runner.invoke(app, ["scan", "scanme.nmap.org", "--output", str(tmp_path / "scans")])
    assert result.exit_code == 0, result.output
    assert "Report written" not in result.output
    assert not (tmp_path / "reports").exists()
