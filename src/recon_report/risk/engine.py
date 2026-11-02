"""Evaluate a parsed scan against the risk rules."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from recon_report.parser import Host, Port, ScanResult
from recon_report.risk.models import Confidence, Finding, ServiceRule, Severity, VersionRule
from recon_report.risk.rules import SERVICE_RULES, VERSION_RULES

BACKPORT_NOTE = (
    "Linux distributions often backport security fixes without changing the upstream "
    "version number, so the banner version may not reflect the actual patch status. "
    "Verify against the vendor's package version before acting."
)

# Service names nmap uses for TLS services when it reports no separate ssl tunnel,
# e.g. from the port table without -sV.
_TLS_SERVICE_NAMES = frozenset({"https", "ftps", "docker-s"})

# A leading dotted number not followed by another dot, so "5.X" is rejected.
_VERSION_RE = re.compile(r"(\d+(?:\.\d+)*)(?![.\d])")
_UNCERTAIN_VERSION_MARKERS = (" - ", "or later", "or earlier")


@dataclass(frozen=True, slots=True)
class Assessment:
    """Findings for a scan, sorted most severe first."""

    findings: tuple[Finding, ...]

    @property
    def counts(self) -> dict[Severity, int]:
        """Number of findings per severity, from Critical down to Info."""
        return severity_counts(self.findings)

    def at_or_above(self, severity: Severity) -> tuple[Finding, ...]:
        """Findings whose severity is ``severity`` or higher."""
        return tuple(finding for finding in self.findings if finding.severity >= severity)


def assess(
    result: ScanResult,
    service_rules: Sequence[ServiceRule] = SERVICE_RULES,
    version_rules: Sequence[VersionRule] = VERSION_RULES,
) -> Assessment:
    """Evaluate every open port on every up host against the rules.

    Args:
        result: Parsed scan result from :mod:`recon_report.parser`.
        service_rules: Service-exposure rules; defaults to :data:`SERVICE_RULES`.
        version_rules: Version rules; defaults to :data:`VERSION_RULES`.

    Returns:
        The findings, sorted by severity (most severe first), then host, port and rule ID.
    """
    findings: list[Finding] = []
    for host in result.hosts_up:
        for port in host.open_ports:
            for service_rule in _matching_service_rules(port, service_rules):
                findings.append(_service_finding(service_rule, host, port))
            for version_rule in version_rules:
                if version_rule_matches(version_rule, port):
                    findings.append(_version_finding(version_rule, host, port))
    return Assessment(findings=tuple(sorted(findings, key=_sort_key)))


def severity_counts(findings: Iterable[Finding]) -> dict[Severity, int]:
    """Count findings per severity. Every severity is present, ordered Critical to Info."""
    counts = dict.fromkeys(sorted(Severity, reverse=True), 0)
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def parse_version(text: str | None) -> tuple[int, ...] | None:
    """Extract the leading numeric version from an nmap version string.

    ``"6.6.1p1 Ubuntu 2ubuntu2.13"`` gives ``(6, 6, 1)``. Returns ``None`` when there
    is no usable version, or when it is uncertain: wildcards (``"5.X"``), ranges
    (``"2.0.0 - 2.0.10"``) and bounds (``"9.6.0 or later"``).
    """
    if not text:
        return None
    if any(marker in text.lower() for marker in _UNCERTAIN_VERSION_MARKERS):
        return None
    match = _VERSION_RE.match(text.strip())
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def compare_versions(left: Sequence[int], right: Sequence[int]) -> int:
    """Compare two numeric versions, padding the shorter with zeros.

    Returns a negative number, zero or a positive number, like ``cmp``.
    """
    length = max(len(left), len(right))
    padded_left = tuple(left) + (0,) * (length - len(left))
    padded_right = tuple(right) + (0,) * (length - len(right))
    return (padded_left > padded_right) - (padded_left < padded_right)


def version_rule_matches(rule: VersionRule, port: Port) -> bool:
    """Whether ``rule`` applies to the product and version nmap reported for ``port``."""
    if not port.product or port.product.casefold() not in {p.casefold() for p in rule.products}:
        return False
    banner = port.banner.casefold()
    if any(excluded.casefold() in banner for excluded in rule.exclude):
        return False
    version = parse_version(port.version)
    if version is None:
        return False
    if rule.below is not None:
        threshold = parse_version(rule.below)
        return threshold is not None and compare_versions(version, threshold) < 0
    return any(
        (exact := parse_version(candidate)) is not None and compare_versions(version, exact) == 0
        for candidate in rule.versions
    )


def is_tls(port: Port) -> bool:
    """Whether nmap reported the service as running inside TLS."""
    return port.tunnel == "ssl" or (port.service_name or "").casefold() in _TLS_SERVICE_NAMES


def _matching_service_rules(port: Port, rules: Sequence[ServiceRule]) -> list[ServiceRule]:
    matched = [rule for rule in rules if _service_rule_matches(rule, port)]
    specific = [rule for rule in matched if not rule.fallback]
    return specific or matched


def _service_rule_matches(rule: ServiceRule, port: Port) -> bool:
    if rule.tls is not None and rule.tls != is_tls(port):
        return False
    name = (port.service_name or "").casefold()
    if name and name in {service.casefold() for service in rule.services}:
        return True
    product = (port.product or "").casefold()
    return bool(product) and any(p.casefold() in product for p in rule.products)


def _service_finding(rule: ServiceRule, host: Host, port: Port) -> Finding:
    confidence = Confidence.CONFIRMED if port.method == "probed" else Confidence.LIKELY
    return _finding(rule, host, port, confidence, rule.description)


def _version_finding(rule: VersionRule, host: Host, port: Port) -> Finding:
    return _finding(rule, host, port, Confidence.POTENTIAL, f"{rule.description} {BACKPORT_NOTE}")


def _finding(
    rule: ServiceRule | VersionRule,
    host: Host,
    port: Port,
    confidence: Confidence,
    description: str,
) -> Finding:
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        confidence=confidence,
        host=host.address,
        hostname=host.hostnames[0] if host.hostnames else None,
        port=port.port,
        protocol=port.protocol,
        evidence=_evidence(port),
        description=description,
        recommendation=rule.recommendation,
        references=rule.references,
    )


def _evidence(port: Port) -> str:
    """Service name and banner, e.g. ``"ssl/http: nginx 1.24.0"``, as nmap prints them."""
    name = port.service_name or "unknown"
    if port.tunnel == "ssl":
        name = f"ssl/{name}"
    return f"{name}: {port.banner}" if port.banner else name


def _sort_key(finding: Finding) -> tuple[int, tuple[int, int, str], int, str, str]:
    return (
        -finding.severity,
        _address_key(finding.host),
        finding.port,
        finding.protocol,
        finding.rule_id,
    )


def _address_key(address: str) -> tuple[int, int, str]:
    """Sort IP addresses numerically (IPv4 before IPv6) and anything else after, by text."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return (1, 0, address)
    return (0, ip.version, f"{int(ip):039d}")
