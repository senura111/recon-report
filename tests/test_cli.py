"""Tests for the recon-report CLI. nmap is never executed."""

from __future__ import annotations

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
