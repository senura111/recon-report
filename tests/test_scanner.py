"""Tests for recon_report.scanner. nmap is never executed."""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from recon_report import scanner

FAKE_NMAP = "/usr/bin/nmap"


class FakeRun:
    """Stand-in for subprocess.run that records calls and writes the -oX file."""

    def __init__(self, returncode: int = 0, stderr: str = "", write_xml: bool = True) -> None:
        self.returncode = returncode
        self.stderr = stderr
        self.write_xml = write_xml
        self.calls: list[tuple[list[str], dict]] = []

    def __call__(self, args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        self.calls.append((args, kwargs))
        if self.write_xml:
            Path(args[args.index("-oX") + 1]).write_text("<nmaprun/>", encoding="utf-8")
        return subprocess.CompletedProcess(args, self.returncode, stdout="", stderr=self.stderr)


@pytest.fixture
def nmap_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanner.shutil, "which", lambda name: FAKE_NMAP)


@pytest.fixture
def fake_run(monkeypatch: pytest.MonkeyPatch, nmap_installed: None) -> FakeRun:
    fake = FakeRun()
    monkeypatch.setattr(scanner.subprocess, "run", fake)
    return fake


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("192.168.56.101", "192.168.56.101"),
        ("  10.0.0.5 ", "10.0.0.5"),
        ("::1", "::1"),
        ("2001:DB8::1", "2001:db8::1"),
        ("scanme.nmap.org", "scanme.nmap.org"),
        ("ScanMe.Nmap.Org.", "scanme.nmap.org"),
        ("localhost", "localhost"),
        ("lab-vm01", "lab-vm01"),
    ],
)
def test_validate_target_accepts_single_hosts(target: str, expected: str) -> None:
    assert scanner.validate_target(target) == expected


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        "-oX",
        "--script=vuln",
        "10.0.0.0/24",
        "10.0.0.1-20",
        "10.0-5.0.1",
        "10.0.0.1 10.0.0.2",
        "10.0.0.1,10.0.0.2",
        "*.example.com",
        "999.1.1.1",
        "bad_host.example.com",
        "-leading.example.com",
        "a" * 64 + ".com",
        "host;rm -rf /",
    ],
)
def test_validate_target_rejects_invalid(target: str) -> None:
    with pytest.raises(scanner.InvalidTargetError):
        scanner.validate_target(target)


@pytest.mark.parametrize(
    ("ports", "expected"),
    [("22", "22"), ("22,80,443", "22,80,443"), ("1-1024", "1-1024"), ("22, 80", "22,80")],
)
def test_validate_ports_accepts_valid(ports: str, expected: str) -> None:
    assert scanner.validate_ports(ports) == expected


@pytest.mark.parametrize("ports", ["", "0", "65536", "80-22", "22,", "abc", "-p", "T:22", "1-2-3"])
def test_validate_ports_rejects_invalid(ports: str) -> None:
    with pytest.raises(scanner.InvalidTargetError):
        scanner.validate_ports(ports)


def test_build_output_path_is_timestamped_and_filename_safe(tmp_path: Path) -> None:
    now = datetime(2026, 11, 2, 9, 30, 15, tzinfo=timezone.utc)
    path = scanner.build_output_path(tmp_path, "2001:db8::1", now=now)
    assert path == tmp_path / "scan_2001_db8__1_20261102T093015Z.xml"


def test_find_nmap_raises_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanner.shutil, "which", lambda name: None)
    with pytest.raises(scanner.NmapNotFoundError, match="not found"):
        scanner.find_nmap()


def test_run_scan_builds_safe_argument_list(fake_run: FakeRun, tmp_path: Path) -> None:
    out_dir = tmp_path / "nested" / "scans"
    xml_path = scanner.run_scan("scanme.nmap.org", out_dir, ports="22,80", timeout=30)

    assert xml_path.is_file()
    assert xml_path.parent == out_dir
    assert xml_path.name.startswith("scan_scanme.nmap.org_")
    assert xml_path.suffix == ".xml"

    (args, kwargs) = fake_run.calls[0]
    assert args == [FAKE_NMAP, "-sV", "-oX", str(xml_path), "-p", "22,80", "scanme.nmap.org"]
    assert kwargs["timeout"] == 30
    assert "shell" not in kwargs


def test_run_scan_without_ports_omits_port_flag(fake_run: FakeRun, tmp_path: Path) -> None:
    scanner.run_scan("10.0.0.5", tmp_path)
    args, kwargs = fake_run.calls[0]
    assert "-p" not in args
    assert args[-1] == "10.0.0.5"
    assert kwargs["timeout"] == scanner.DEFAULT_TIMEOUT_SECONDS


def test_run_scan_adds_ipv6_flag(fake_run: FakeRun, tmp_path: Path) -> None:
    scanner.run_scan("::1", tmp_path)
    args, _ = fake_run.calls[0]
    assert "-6" in args
    assert args[-1] == "::1"


def test_run_scan_validates_before_checking_nmap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(scanner.shutil, "which", lambda name: None)
    with pytest.raises(scanner.InvalidTargetError):
        scanner.run_scan("10.0.0.0/8", tmp_path)


def test_run_scan_rejects_non_positive_timeout(fake_run: FakeRun, tmp_path: Path) -> None:
    with pytest.raises(scanner.InvalidTargetError, match="Timeout"):
        scanner.run_scan("10.0.0.5", tmp_path, timeout=0)
    assert fake_run.calls == []


def test_run_scan_raises_when_nmap_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(scanner.shutil, "which", lambda name: None)
    with pytest.raises(scanner.NmapNotFoundError):
        scanner.run_scan("10.0.0.5", tmp_path)


def test_run_scan_timeout_removes_partial_xml(
    monkeypatch: pytest.MonkeyPatch, nmap_installed: None, tmp_path: Path
) -> None:
    def timed_out(args: list[str], **kwargs: object) -> None:
        Path(args[args.index("-oX") + 1]).write_text("<nmaprun", encoding="utf-8")
        raise subprocess.TimeoutExpired(args, kwargs["timeout"])

    monkeypatch.setattr(scanner.subprocess, "run", timed_out)
    with pytest.raises(scanner.ScanTimeoutError, match="timed out after 5 seconds"):
        scanner.run_scan("10.0.0.5", tmp_path, timeout=5)
    assert list(tmp_path.iterdir()) == []


def test_run_scan_nonzero_exit_raises_execution_error(
    monkeypatch: pytest.MonkeyPatch, nmap_installed: None, tmp_path: Path
) -> None:
    fake = FakeRun(returncode=1, stderr="Failed to resolve host", write_xml=False)
    monkeypatch.setattr(scanner.subprocess, "run", fake)
    with pytest.raises(scanner.NmapExecutionError, match="code 1: Failed to resolve host"):
        scanner.run_scan("10.0.0.5", tmp_path)


def test_run_scan_missing_xml_raises_execution_error(
    monkeypatch: pytest.MonkeyPatch, nmap_installed: None, tmp_path: Path
) -> None:
    monkeypatch.setattr(scanner.subprocess, "run", FakeRun(write_xml=False))
    with pytest.raises(scanner.NmapExecutionError, match="did not write"):
        scanner.run_scan("10.0.0.5", tmp_path)


def test_run_scan_os_error_raises_execution_error(
    monkeypatch: pytest.MonkeyPatch, nmap_installed: None, tmp_path: Path
) -> None:
    def broken(args: list[str], **kwargs: object) -> None:
        raise PermissionError("access denied")

    monkeypatch.setattr(scanner.subprocess, "run", broken)
    with pytest.raises(scanner.NmapExecutionError, match="access denied"):
        scanner.run_scan("10.0.0.5", tmp_path)


def test_exceptions_share_base_class() -> None:
    for exc in (
        scanner.NmapNotFoundError,
        scanner.InvalidTargetError,
        scanner.ScanTimeoutError,
        scanner.NmapExecutionError,
    ):
        assert issubclass(exc, scanner.ScanError)
