"""Run Nmap service discovery against a single target and store the XML output."""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from recon_report import filenames

DEFAULT_TIMEOUT_SECONDS = 600

_HOSTNAME_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_PORT_ITEM = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")


class ScanError(Exception):
    """Base class for all scanner errors."""


class NmapNotFoundError(ScanError):
    """Raised when the nmap executable cannot be found on PATH."""


class InvalidTargetError(ScanError):
    """Raised when a scan target or port specification is invalid."""


class ScanTimeoutError(ScanError):
    """Raised when nmap does not finish within the allowed time."""


class NmapExecutionError(ScanError):
    """Raised when nmap fails to run or exits with an error."""


def validate_target(target: str) -> str:
    """Validate a single scan target and return it in normalized form.

    Accepts one IPv4 address, one IPv6 address, or one hostname. Ranges, CIDR
    blocks, lists, wildcards and anything that looks like a command-line option
    are rejected.

    Raises:
        InvalidTargetError: If the target is not a single valid host.
    """
    candidate = target.strip()
    if not candidate:
        raise InvalidTargetError("Target must not be empty.")
    if candidate.startswith("-"):
        raise InvalidTargetError(f"Target must not start with '-': {target!r}")

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass

    hostname = candidate[:-1] if candidate.endswith(".") else candidate
    labels = hostname.split(".")
    # The last label must contain a letter so nmap octet ranges like
    # "10.0.0.1-20" or malformed IPs like "999.1.1.1" are not taken as hostnames.
    if (
        len(hostname) > 253
        or not all(_HOSTNAME_LABEL.match(label) for label in labels)
        or not any(char.isalpha() for char in labels[-1])
    ):
        raise InvalidTargetError(
            f"Invalid target {target!r}: expected a single IP address or hostname."
        )
    return hostname.lower()


def validate_ports(ports: str) -> str:
    """Validate an Nmap port specification such as ``22,80,8000-8100``.

    Raises:
        InvalidTargetError: If the specification is malformed or out of range.
    """
    spec = ports.replace(" ", "")
    if not spec:
        raise InvalidTargetError("Port specification must not be empty.")

    for item in spec.split(","):
        match = _PORT_ITEM.match(item)
        if not match:
            raise InvalidTargetError(f"Invalid port specification {ports!r}: bad item {item!r}.")
        start = int(match.group(1))
        end = int(match.group(2) or start)
        if not (1 <= start <= 65535 and 1 <= end <= 65535):
            raise InvalidTargetError(f"Port out of range (1-65535) in {ports!r}: {item!r}.")
        if start > end:
            raise InvalidTargetError(f"Port range start exceeds end in {ports!r}: {item!r}.")
    return spec


def find_nmap() -> str:
    """Return the path to the nmap executable.

    Raises:
        NmapNotFoundError: If nmap is not installed or not on PATH.
    """
    path = shutil.which("nmap")
    if path is None:
        raise NmapNotFoundError(
            "nmap was not found on PATH. Install it from https://nmap.org/download.html."
        )
    return path


def build_output_path(output_dir: Path, target: str, now: datetime | None = None) -> Path:
    """Return a timestamped XML output path for ``target`` inside ``output_dir``."""
    return output_dir / f"scan_{filenames.safe_part(target)}_{filenames.timestamp(now)}.xml"


def run_scan(
    target: str,
    output_dir: Path,
    ports: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> Path:
    """Run an Nmap service version scan (``-sV``) against a single target.

    Args:
        target: One IP address or hostname you are authorized to scan.
        output_dir: Directory for the XML output; created if missing.
        ports: Optional port specification, e.g. ``"22,80,443"`` or ``"1-1024"``.
        timeout: Maximum scan duration in seconds.

    Returns:
        Path to the saved Nmap XML file.

    Raises:
        InvalidTargetError: If the target, ports or timeout are invalid.
        NmapNotFoundError: If nmap is not installed.
        ScanTimeoutError: If the scan exceeds ``timeout``.
        NmapExecutionError: If nmap fails to start, exits non-zero, or writes no XML.
    """
    host = validate_target(target)
    port_spec = validate_ports(ports) if ports is not None else None
    if timeout <= 0:
        raise InvalidTargetError(f"Timeout must be positive, got {timeout}.")
    nmap = find_nmap()

    output_dir.mkdir(parents=True, exist_ok=True)
    xml_path = build_output_path(output_dir, host)

    args = [nmap, "-sV", "-oX", str(xml_path)]
    if _is_ipv6(host):
        args.append("-6")
    if port_spec is not None:
        args += ["-p", port_spec]
    args.append(host)

    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        xml_path.unlink(missing_ok=True)
        raise ScanTimeoutError(f"Scan of {host} timed out after {timeout:g} seconds.") from exc
    except OSError as exc:
        raise NmapExecutionError(f"Failed to run nmap: {exc}") from exc

    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or "no output"
        raise NmapExecutionError(f"nmap exited with code {result.returncode}: {detail}")
    if not xml_path.is_file():
        raise NmapExecutionError(f"nmap finished but did not write {xml_path}.")
    return xml_path


def _is_ipv6(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 6
    except ValueError:
        return False
