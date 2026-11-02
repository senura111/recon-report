"""Tests for recon_report.risk using XML fixtures and hand-built ports. nmap is never executed."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from recon_report.parser import Host, Port, ScanResult, parse_file
from recon_report.risk import (
    BACKPORT_NOTE,
    SERVICE_RULES,
    VERSION_RULES,
    Confidence,
    Finding,
    ServiceRule,
    Severity,
    VersionRule,
    assess,
    compare_versions,
    parse_version,
    severity_counts,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _port(port: int = 1234, protocol: str = "tcp", state: str = "open", **fields: str) -> Port:
    fields.setdefault("method", "probed")
    return Port(port=port, protocol=protocol, state=state, **fields)


def _scan(*ports: Port, address: str = "10.0.0.5", status: str = "up") -> ScanResult:
    host = Host(address=address, address_type="ipv4", status=status, ports=ports)
    return ScanResult(nmap_version=None, args=None, start_time=None, end_time=None, hosts=(host,))


def _rule_ids(*ports: Port) -> list[str]:
    return [finding.rule_id for finding in assess(_scan(*ports)).findings]


# --- Severity and confidence ----------------------------------------------------


def test_severity_is_ordered() -> None:
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert sorted(Severity, reverse=True)[0] is Severity.CRITICAL


@pytest.mark.parametrize("text", ["high", "High", "HIGH", " high "])
def test_severity_parse_is_case_insensitive(text: str) -> None:
    assert Severity.parse(text) is Severity.HIGH


def test_severity_parse_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="Unknown severity 'severe'"):
        Severity.parse("severe")


def test_severity_and_confidence_display() -> None:
    assert str(Severity.CRITICAL) == "Critical"
    assert str(Confidence.POTENTIAL) == "potential"


# --- Rule definitions -----------------------------------------------------------


def test_rule_ids_are_unique() -> None:
    ids = [rule.rule_id for rule in (*SERVICE_RULES, *VERSION_RULES)]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("rule", [*SERVICE_RULES, *VERSION_RULES], ids=lambda rule: rule.rule_id)
def test_every_rule_has_rationale_recommendation_and_https_references(
    rule: ServiceRule | VersionRule,
) -> None:
    assert rule.title.strip()
    assert len(rule.description) > 40
    assert len(rule.recommendation) > 20
    assert all(reference.startswith("https://") for reference in rule.references)


@pytest.mark.parametrize("rule", VERSION_RULES, ids=lambda rule: rule.rule_id)
def test_every_version_rule_has_review_date(rule: VersionRule) -> None:
    assert isinstance(rule.last_reviewed, date)
    assert rule.last_reviewed <= date.today()


def test_service_rule_requires_a_matcher() -> None:
    with pytest.raises(ValueError, match="at least one service or product"):
        ServiceRule(
            rule_id="X", title="x", severity=Severity.LOW, description="d", recommendation="r"
        )


@pytest.mark.parametrize(("below", "versions"), [(None, ()), ("1.0", ("1.0",))])
def test_version_rule_requires_exactly_one_condition(
    below: str | None, versions: tuple[str, ...]
) -> None:
    with pytest.raises(ValueError, match="exactly one of below or versions"):
        VersionRule(
            rule_id="X",
            title="x",
            severity=Severity.LOW,
            description="d",
            recommendation="r",
            products=("p",),
            last_reviewed=date(2026, 1, 1),
            below=below,
            versions=versions,
        )


# --- Service-exposure rules -----------------------------------------------------


@pytest.mark.parametrize(
    ("service", "rule_id", "severity"),
    [
        ("telnet", "RR-CLEARTEXT-TELNET", Severity.HIGH),
        ("login", "RR-CLEARTEXT-RSERVICES", Severity.HIGH),
        ("shell", "RR-CLEARTEXT-RSERVICES", Severity.HIGH),
        ("exec", "RR-CLEARTEXT-RSERVICES", Severity.HIGH),
        ("ftp", "RR-CLEARTEXT-FTP", Severity.MEDIUM),
        ("http", "RR-CLEARTEXT-HTTP", Severity.LOW),
    ],
)
def test_cleartext_protocols(service: str, rule_id: str, severity: Severity) -> None:
    (finding,) = assess(_scan(_port(service_name=service))).findings
    assert (finding.rule_id, finding.severity) == (rule_id, severity)


@pytest.mark.parametrize(
    ("service", "rule_id"),
    [
        ("ms-wbt-server", "RR-REMOTE-RDP"),
        ("vnc", "RR-REMOTE-VNC"),
        ("microsoft-ds", "RR-REMOTE-SMB"),
        ("netbios-ssn", "RR-REMOTE-SMB"),
    ],
)
def test_remote_admin_services_are_high(service: str, rule_id: str) -> None:
    (finding,) = assess(_scan(_port(service_name=service))).findings
    assert (finding.rule_id, finding.severity) == (rule_id, Severity.HIGH)


@pytest.mark.parametrize(
    ("fields", "rule_id", "severity"),
    [
        ({"service_name": "mysql"}, "RR-DB-MYSQL", Severity.MEDIUM),
        ({"service_name": "postgresql"}, "RR-DB-POSTGRESQL", Severity.MEDIUM),
        ({"service_name": "ms-sql-s"}, "RR-DB-MSSQL", Severity.MEDIUM),
        ({"service_name": "mongodb"}, "RR-DB-MONGODB", Severity.HIGH),
        ({"service_name": "redis"}, "RR-DB-REDIS", Severity.HIGH),
        ({"service_name": "docker"}, "RR-API-DOCKER", Severity.CRITICAL),
        ({"service_name": "docker", "tunnel": "ssl"}, "RR-API-DOCKER-TLS", Severity.MEDIUM),
        ({"service_name": "docker-s"}, "RR-API-DOCKER-TLS", Severity.MEDIUM),
    ],
)
def test_databases_and_management_apis(
    fields: dict[str, str], rule_id: str, severity: Severity
) -> None:
    (finding,) = assess(_scan(_port(**fields))).findings
    assert (finding.rule_id, finding.severity) == (rule_id, severity)


def test_service_names_match_case_insensitively() -> None:
    assert _rule_ids(_port(service_name="Telnet")) == ["RR-CLEARTEXT-TELNET"]


def test_product_match_for_service_reported_as_http() -> None:
    # nmap reports Elasticsearch as http; the specific rule suppresses the HTTP fallback.
    port = _port(service_name="http", product="Elasticsearch REST API", version="7.17.0")
    assert _rule_ids(port) == ["RR-DB-ELASTICSEARCH"]


@pytest.mark.parametrize(
    "fields",
    [
        {"service_name": "http", "tunnel": "ssl"},
        {"service_name": "https"},
        {"service_name": "telnet", "tunnel": "ssl"},
        {"service_name": "ftp", "tunnel": "ssl"},
    ],
)
def test_tls_tunnelled_cleartext_services_are_not_flagged(fields: dict[str, str]) -> None:
    assert _rule_ids(_port(**fields)) == []


def test_tls_does_not_hide_exposure_rules() -> None:
    assert _rule_ids(_port(service_name="redis", tunnel="ssl")) == ["RR-DB-REDIS"]


@pytest.mark.parametrize("service", ["ssh", "msrpc", "domain", None])
def test_unflagged_services(service: str | None) -> None:
    fields = {"service_name": service} if service else {}
    assert _rule_ids(_port(**fields)) == []


@pytest.mark.parametrize(
    ("method", "confidence"),
    [
        ("probed", Confidence.CONFIRMED),
        ("table", Confidence.LIKELY),
        (None, Confidence.LIKELY),
    ],
)
def test_service_confidence_follows_detection_method(
    method: str | None, confidence: Confidence
) -> None:
    port = Port(port=23, protocol="tcp", state="open", service_name="telnet", method=method)
    (finding,) = assess(_scan(port)).findings
    assert finding.confidence is confidence


@pytest.mark.parametrize("state", ["closed", "filtered", "open|filtered"])
def test_only_open_ports_are_assessed(state: str) -> None:
    assert _rule_ids(_port(state=state, service_name="telnet")) == []


def test_down_hosts_are_not_assessed() -> None:
    assert assess(_scan(_port(service_name="telnet"), status="down")).findings == ()


def test_finding_fields() -> None:
    port = Port(
        port=992,
        protocol="tcp",
        state="open",
        service_name="telnet",
        product="Linux telnetd",
        extra_info="lab",
        method="probed",
    )
    host = Host(
        address="10.0.0.5", address_type="ipv4", status="up", hostnames=("a", "b"), ports=(port,)
    )
    result = ScanResult(nmap_version=None, args=None, start_time=None, end_time=None, hosts=(host,))

    (finding,) = assess(result).findings
    rule = next(rule for rule in SERVICE_RULES if rule.rule_id == "RR-CLEARTEXT-TELNET")
    assert finding == Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        host="10.0.0.5",
        hostname="a",
        port=992,
        protocol="tcp",
        evidence="telnet: Linux telnetd (lab)",
        description=rule.description,
        recommendation=rule.recommendation,
        references=rule.references,
    )


def test_evidence_shows_ssl_tunnel_like_nmap() -> None:
    port = _port(service_name="docker", product="Docker", version="24.0.7", tunnel="ssl")
    (finding,) = assess(_scan(port)).findings
    assert finding.evidence == "ssl/docker: Docker 24.0.7"


def test_custom_rules_can_be_passed_in() -> None:
    rule = ServiceRule(
        rule_id="LAB-SSH",
        title="SSH exposed",
        severity=Severity.INFO,
        services=("ssh",),
        description="d",
        recommendation="r",
    )
    result = assess(_scan(_port(service_name="ssh")), service_rules=[rule], version_rules=[])
    assert [finding.rule_id for finding in result.findings] == ["LAB-SSH"]


# --- Version rules --------------------------------------------------------------


@pytest.mark.parametrize(
    ("product", "version", "rule_id"),
    [
        ("OpenSSH", "7.3p1", "RR-VER-OPENSSH-OUTDATED"),
        ("OpenSSH", "6.6.1p1 Ubuntu 2ubuntu2.13", "RR-VER-OPENSSH-OUTDATED"),
        ("Apache httpd", "2.2.34", "RR-VER-APACHE-EOL"),
        ("Apache httpd", "1.3.42", "RR-VER-APACHE-EOL"),
        ("Apache httpd", "2.4.49", "RR-VER-APACHE-PATH-TRAVERSAL"),
        ("Apache httpd", "2.4.50", "RR-VER-APACHE-PATH-TRAVERSAL"),
        ("vsftpd", "2.3.4", "RR-VER-VSFTPD-BACKDOOR"),
        ("Microsoft IIS httpd", "7.5", "RR-VER-IIS-EOL"),
        ("Microsoft IIS httpd", "8.5", "RR-VER-IIS-EOL"),
        ("MySQL", "5.7.44", "RR-VER-MYSQL-EOL"),
        ("MySQL", "8.0.36-0ubuntu0.22.04.1", "RR-VER-MYSQL-EOL"),
        ("MySQL", "8.3.0", "RR-VER-MYSQL-EOL"),
        ("PostgreSQL DB", "13.16", "RR-VER-POSTGRESQL-EOL"),
        ("PostgreSQL DB", "9.6", "RR-VER-POSTGRESQL-EOL"),
    ],
)
def test_version_rules_flag_outdated_versions(product: str, version: str, rule_id: str) -> None:
    findings = assess(_scan(_port(product=product, version=version))).findings
    (finding,) = (finding for finding in findings if finding.rule_id.startswith("RR-VER-"))
    assert finding.rule_id == rule_id
    assert finding.confidence is Confidence.POTENTIAL
    assert finding.description.endswith(BACKPORT_NOTE)


@pytest.mark.parametrize(
    ("product", "version"),
    [
        ("OpenSSH", "7.4"),
        ("OpenSSH", "7.4p1"),
        ("OpenSSH", "9.6p1 Ubuntu 3ubuntu13.5"),
        ("Apache httpd", "2.4"),
        ("Apache httpd", "2.4.48"),
        ("Apache httpd", "2.4.51"),
        ("Apache httpd", "2.4.7"),
        ("vsftpd", "2.3.5"),
        ("vsftpd", "3.0.5"),
        ("Microsoft IIS httpd", "10.0"),
        ("MySQL", "8.4.3"),
        ("MySQL", "9.1.0"),
        ("PostgreSQL DB", "14.13"),
        ("PostgreSQL DB", "16.4"),
        # Uncertain or missing versions are never flagged.
        ("OpenSSH", None),
        ("OpenSSH", ""),
        ("OpenSSH", "5.X"),
        ("Apache httpd", "2.2.X - 2.4.X"),
        ("PostgreSQL DB", "9.6.0 - 9.6.4"),
        ("PostgreSQL DB", "9.6.0 or later"),
        # Product names must match exactly, not as substrings.
        ("Apache Tomcat", "2.0"),
        ("Dropbear sshd", "2016.74"),
    ],
)
def test_version_rules_ignore_current_or_uncertain_versions(
    product: str, version: str | None
) -> None:
    fields = {"product": product} if version is None else {"product": product, "version": version}
    rule_ids = _rule_ids(_port(**fields))
    assert not [rule_id for rule_id in rule_ids if rule_id.startswith("RR-VER-")]


def test_mariadb_banner_is_not_mistaken_for_old_mysql() -> None:
    port = _port(service_name="mysql", product="MySQL", version="5.5.5-10.6.12-MariaDB")
    assert _rule_ids(port) == ["RR-DB-MYSQL"]


def test_version_product_match_is_case_insensitive() -> None:
    assert "RR-VER-OPENSSH-OUTDATED" in _rule_ids(_port(product="openssh", version="5.3"))


# --- Version parsing and comparison ---------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2.4.7", (2, 4, 7)),
        ("6.6.1p1 Ubuntu 2ubuntu2.13", (6, 6, 1)),
        ("8.0.36-0ubuntu0.22.04.1", (8, 0, 36)),
        ("5.5.5-10.6.12-MariaDB", (5, 5, 5)),
        ("10.0", (10, 0)),
        ("14", (14,)),
        (" 1.2 ", (1, 2)),
        ("5.X", None),
        ("2.4.x", None),
        ("2.0.0 - 2.0.10", None),
        ("9.6.0 or later", None),
        ("unknown", None),
        ("", None),
        (None, None),
    ],
)
def test_parse_version(text: str | None, expected: tuple[int, ...] | None) -> None:
    assert parse_version(text) == expected


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ((2, 4, 10), (2, 4, 9), 1),  # numeric, not lexical
        ((2, 4), (2, 4, 0), 0),  # missing parts count as zero
        ((2, 4, 0, 1), (2, 4), 1),
        ((7, 3), (7, 4), -1),
        ((10, 0), (9, 99), 1),
        ((1,), (1,), 0),
    ],
)
def test_compare_versions(left: tuple[int, ...], right: tuple[int, ...], expected: int) -> None:
    assert compare_versions(left, right) == expected
    assert compare_versions(right, left) == -expected


# --- Sorting and counts ---------------------------------------------------------


def test_findings_sorted_by_severity_then_host_then_port() -> None:
    result = parse_file(FIXTURES / "risky_host.xml")
    findings = assess(result).findings

    severities = [finding.severity for finding in findings]
    assert severities == sorted(severities, reverse=True)
    # IPs sort numerically: 10.0.0.3 comes before 10.0.0.20 within a severity.
    high = [(f.host, f.port) for f in findings if f.severity is Severity.HIGH]
    assert high == [
        ("10.0.0.3", 5900),
        ("10.0.0.20", 23),
        ("10.0.0.20", 3389),
        ("10.0.0.20", 6379),
        ("10.0.0.20", 8080),
        ("10.0.0.20", 9200),
    ]


def test_severity_counts_include_every_severity_in_order() -> None:
    counts = severity_counts([])
    assert list(counts) == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    assert set(counts.values()) == {0}


def test_assessment_counts_and_threshold() -> None:
    assessment = assess(parse_file(FIXTURES / "risky_host.xml"))
    assert assessment.counts == {
        Severity.CRITICAL: 1,
        Severity.HIGH: 6,
        Severity.MEDIUM: 2,
        Severity.LOW: 1,
        Severity.INFO: 0,
    }
    assert len(assessment.at_or_above(Severity.HIGH)) == 7
    assert len(assessment.at_or_above(Severity.INFO)) == len(assessment.findings)


# --- Fixtures -------------------------------------------------------------------


def test_risky_host_fixture() -> None:
    findings = assess(parse_file(FIXTURES / "risky_host.xml")).findings
    by_port = {}
    for finding in findings:
        by_port.setdefault(finding.port, []).append(finding.rule_id)

    assert by_port == {
        23: ["RR-CLEARTEXT-TELNET"],
        2375: ["RR-API-DOCKER"],
        3306: ["RR-DB-MYSQL"],
        3389: ["RR-REMOTE-RDP"],
        5432: ["RR-DB-POSTGRESQL"],
        5900: ["RR-REMOTE-VNC"],
        6379: ["RR-DB-REDIS"],
        8080: ["RR-VER-APACHE-PATH-TRAVERSAL", "RR-CLEARTEXT-HTTP"],
        9200: ["RR-DB-ELASTICSEARCH"],
    }
    rdp = next(finding for finding in findings if finding.port == 3389)
    assert rdp.confidence is Confidence.LIKELY


def test_real_scanme_fixture() -> None:
    assessment = assess(parse_file(FIXTURES / "single_host.xml"))

    ssh, http = assessment.findings
    assert (ssh.rule_id, ssh.severity, ssh.confidence) == (
        "RR-VER-OPENSSH-OUTDATED",
        Severity.MEDIUM,
        Confidence.POTENTIAL,
    )
    assert (ssh.host, ssh.hostname, ssh.port) == ("45.33.32.156", "scanme.nmap.org", 22)
    assert ssh.evidence == "ssh: OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)"
    assert BACKPORT_NOTE in ssh.description

    assert (http.rule_id, http.severity, http.confidence) == (
        "RR-CLEARTEXT-HTTP",
        Severity.LOW,
        Confidence.CONFIRMED,
    )
    assert http.evidence == "http: Apache httpd 2.4.7 ((Ubuntu))"
    assert assessment.counts[Severity.MEDIUM] == 1
    assert assessment.counts[Severity.LOW] == 1


def test_multi_host_fixture() -> None:
    findings = assess(parse_file(FIXTURES / "multi_host.xml")).findings
    assert [(f.host, f.port, f.rule_id) for f in findings] == [
        ("192.168.56.101", 21, "RR-VER-VSFTPD-BACKDOOR"),
        ("192.168.56.102", 139, "RR-REMOTE-SMB"),
        ("192.168.56.102", 445, "RR-REMOTE-SMB"),
        ("192.168.56.101", 21, "RR-CLEARTEXT-FTP"),
        ("192.168.56.101", 22, "RR-VER-OPENSSH-OUTDATED"),
        ("192.168.56.101", 80, "RR-VER-APACHE-EOL"),
        ("192.168.56.101", 80, "RR-CLEARTEXT-HTTP"),
    ]
    # Telnet (23) is closed and MySQL (3306) filtered, so neither is reported.
    assert not {23, 3306} & {finding.port for finding in findings}
