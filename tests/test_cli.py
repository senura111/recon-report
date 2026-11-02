"""Tests for the recon-report CLI. nmap is never executed."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from recon_report import __version__, scanner
from recon_report.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_scan_help_lists_options() -> None:
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    for option in ("--output", "--ports", "--timeout"):
        assert option in result.output


def test_scan_passes_options_to_scanner(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[dict] = []

    def fake_run_scan(target: str, output_dir: Path, ports: str | None, timeout: float) -> Path:
        calls.append(
            {"target": target, "output_dir": output_dir, "ports": ports, "timeout": timeout}
        )
        return output_dir / "scan.xml"

    monkeypatch.setattr(scanner, "run_scan", fake_run_scan)
    result = runner.invoke(
        app,
        ["scan", "scanme.nmap.org", "--output", str(tmp_path), "--ports", "22,80", "-t", "60"],
    )

    assert result.exit_code == 0, result.output
    assert calls == [
        {"target": "scanme.nmap.org", "output_dir": tmp_path, "ports": "22,80", "timeout": 60.0}
    ]
    assert "scan.xml" in result.output


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
