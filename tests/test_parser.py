"""Tests for recon_report.parser using XML fixtures. nmap is never executed."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from pathlib import Path

import pytest

from recon_report.parser import Host, ParseError, Port, ScanResult, parse_file, parse_string

FIXTURES = Path(__file__).parent / "fixtures"


def _utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


def _wrap_host(host_xml: str) -> str:
    return f'<nmaprun scanner="nmap">{host_xml}</nmaprun>'


def _wrap_port(port_xml: str) -> str:
    return _wrap_host(
        f'<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>'
        f"<ports>{port_xml}</ports></host>"
    )


def _only_port(port_xml: str) -> Port:
    return parse_string(_wrap_port(port_xml)).hosts[0].ports[0]


# --- Real-world single host (scanme.nmap.org) -----------------------------------


def test_single_host_run_metadata() -> None:
    result = parse_file(FIXTURES / "single_host.xml")

    assert isinstance(result, ScanResult)
    assert result.nmap_version == "7.993"
    assert result.args is not None
    assert "-sV" in result.args
    assert result.args.endswith("-p 22,80 scanme.nmap.org")
    assert result.start_time == _utc(2026, 11, 2, 18, 9, 13)
    assert result.end_time == _utc(2026, 11, 2, 18, 9, 24)


def test_single_host_ignores_hosthint_and_dedupes_hostnames() -> None:
    result = parse_file(FIXTURES / "single_host.xml")

    assert len(result.hosts) == 1
    host = result.hosts[0]
    assert host.address == "45.33.32.156"
    assert host.address_type == "ipv4"
    assert host.status == "up"
    assert host.hostnames == ("scanme.nmap.org",)
    assert host.extra_ports == ()


def test_single_host_ports_are_fully_populated() -> None:
    host = parse_file(FIXTURES / "single_host.xml").hosts[0]

    assert host.ports == (
        Port(
            port=22,
            protocol="tcp",
            state="open",
            reason="syn-ack",
            service_name="ssh",
            product="OpenSSH",
            version="6.6.1p1 Ubuntu 2ubuntu2.13",
            extra_info="Ubuntu Linux; protocol 2.0",
            cpes=("cpe:/a:openbsd:openssh:6.6.1p1", "cpe:/o:linux:linux_kernel"),
            method="probed",
        ),
        Port(
            port=80,
            protocol="tcp",
            state="open",
            reason="syn-ack",
            service_name="http",
            product="Apache httpd",
            version="2.4.7",
            extra_info="(Ubuntu)",
            cpes=("cpe:/a:apache:http_server:2.4.7",),
            method="probed",
        ),
    )
    assert host.open_ports == host.ports


# --- Multiple hosts, down hosts, closed/filtered ports, extraports --------------


@pytest.fixture(scope="module")
def multi_host() -> ScanResult:
    return parse_file(FIXTURES / "multi_host.xml")


def test_multi_host_counts(multi_host: ScanResult) -> None:
    assert [host.address for host in multi_host.hosts] == [
        "192.168.56.101",
        "192.168.56.102",
        "192.168.56.103",
    ]
    assert [host.address for host in multi_host.hosts_up] == ["192.168.56.101", "192.168.56.102"]
    assert multi_host.start_time == _utc(2026, 11, 2, 12, 0, 0)
    assert multi_host.end_time == _utc(2026, 11, 2, 12, 0, 42)


def test_multi_host_prefers_ip_over_mac_address(multi_host: ScanResult) -> None:
    host = multi_host.hosts[0]
    assert host.address == "192.168.56.101"
    assert host.address_type == "ipv4"
    assert host.hostnames == ("metasploitable.lab",)


def test_multi_host_closed_and_filtered_ports(multi_host: ScanResult) -> None:
    host = multi_host.hosts[0]
    states = {port.port: port.state for port in host.ports}
    assert states == {21: "open", 22: "open", 23: "closed", 80: "open", 3306: "filtered"}
    assert [port.port for port in host.open_ports] == [21, 22, 80]

    telnet = next(port for port in host.ports if port.port == 23)
    assert telnet.reason == "reset"
    assert telnet.service_name == "telnet"
    assert telnet.product is None
    assert telnet.version is None
    assert telnet.cpes == ()


def test_multi_host_extra_ports(multi_host: ScanResult) -> None:
    first, second, down = multi_host.hosts
    assert first.extra_ports == (("closed", 993), ("filtered", 2))
    assert second.extra_ports == (("filtered", 997),)
    assert down.extra_ports == ()


def test_multi_host_host_without_hostnames(multi_host: ScanResult) -> None:
    host = multi_host.hosts[1]
    assert host.hostnames == ()
    assert [port.service_name for port in host.open_ports] == [
        "msrpc",
        "netbios-ssn",
        "microsoft-ds",
    ]
    assert host.open_ports[2].product is None


def test_multi_host_down_host(multi_host: ScanResult) -> None:
    host = multi_host.hosts[2]
    assert host.status == "down"
    assert host.address == "192.168.56.103"
    assert host.hostnames == ()
    assert host.ports == ()
    assert host.open_ports == ()


# --- No service detection, IPv6 -------------------------------------------------


def test_no_service_detection() -> None:
    host = parse_file(FIXTURES / "no_service.xml").hosts[0]

    assert host.address == "::1"
    assert host.address_type == "ipv6"
    assert host.hostnames == ("localhost",)

    ssh, ipp, unknown = host.ports
    assert (ssh.service_name, ssh.product, ssh.version, ssh.extra_info) == ("ssh", None, None, None)
    assert ipp.state == "closed"
    assert unknown == Port(port=49999, protocol="tcp", state="open", reason="syn-ack")


# --- Missing optional fields ----------------------------------------------------


def test_minimal_run_has_no_optional_fields() -> None:
    result = parse_file(FIXTURES / "minimal.xml")
    assert result == ScanResult(nmap_version=None, args=None, start_time=None, end_time=None)
    assert result.hosts == ()
    assert result.hosts_up == ()


def test_host_without_status_is_unknown() -> None:
    host = parse_string(_wrap_host('<host><address addr="10.0.0.5" addrtype="ipv4"/></host>'))
    assert host.hosts[0].status == "unknown"


def test_host_with_only_mac_address_uses_it() -> None:
    xml = _wrap_host('<host><address addr="08:00:27:00:00:01" addrtype="mac"/></host>')
    host = parse_string(xml).hosts[0]
    assert (host.address, host.address_type) == ("08:00:27:00:00:01", "mac")


def test_port_without_state_element() -> None:
    port = _only_port('<port protocol="udp" portid="161"/>')
    assert (port.state, port.reason) == ("unknown", None)


def test_blank_attributes_and_empty_cpes_become_none_or_skipped() -> None:
    port = _only_port(
        '<port protocol="tcp" portid="8080"><state state="open" reason=""/>'
        '<service name="http-proxy" product=" " version=""><cpe>  </cpe><cpe/>'
        "<cpe> cpe:/a:example:proxy </cpe></service></port>"
    )
    assert port.reason is None
    assert port.product is None
    assert port.version is None
    assert port.cpes == ("cpe:/a:example:proxy",)


def test_parse_string_accepts_str_and_bytes() -> None:
    xml = (FIXTURES / "single_host.xml").read_text(encoding="utf-8")
    assert parse_string(xml) == parse_string(xml.encode("utf-8"))


def test_results_are_immutable() -> None:
    host = parse_file(FIXTURES / "single_host.xml").hosts[0]
    with pytest.raises(dataclasses.FrozenInstanceError):
        host.status = "down"  # type: ignore[misc]
    assert isinstance(host, Host)


# --- Errors ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "message"),
    [
        ("malformed.xml", "not well-formed XML"),
        ("not_nmap.xml", "root element is <testsuite>, not <nmaprun>"),
        ("xxe.xml", "rejected as unsafe XML"),
        ("billion_laughs.xml", "rejected as unsafe XML"),
    ],
)
def test_bad_fixtures_raise_parse_error(fixture: str, message: str) -> None:
    path = FIXTURES / fixture
    with pytest.raises(ParseError, match=message) as excinfo:
        parse_file(path)
    assert str(path) in str(excinfo.value)


def test_missing_file_raises_parse_error(tmp_path: Path) -> None:
    with pytest.raises(ParseError, match="Cannot read"):
        parse_file(tmp_path / "does-not-exist.xml")


def test_empty_input_raises_parse_error() -> None:
    with pytest.raises(ParseError, match="<string> is not well-formed XML"):
        parse_string(b"")


@pytest.mark.parametrize(
    ("xml", "message"),
    [
        (_wrap_host('<host><status state="up"/></host>'), "Host element has no address"),
        (_wrap_port('<port portid="22"/>'), "Port element has no protocol"),
        (_wrap_port('<port protocol="tcp"/>'), "Missing required portid"),
        (_wrap_port('<port protocol="tcp" portid="ssh"/>'), "Invalid portid: 'ssh'"),
        (
            _wrap_host(
                '<host><address addr="10.0.0.5" addrtype="ipv4"/>'
                '<ports><extraports state="closed"/></ports></host>'
            ),
            "Missing required extraports count",
        ),
        (
            _wrap_host(
                '<host><address addr="10.0.0.5" addrtype="ipv4"/>'
                '<ports><extraports state="closed" count="many"/></ports></host>'
            ),
            "Invalid extraports count",
        ),
        ('<nmaprun start="yesterday"/>', "Invalid start time: 'yesterday' is not an integer"),
        ('<nmaprun start="99999999999999999999"/>', "Invalid start time: .* is out of range"),
        (
            '<nmaprun><runstats><finished time="soon"/></runstats></nmaprun>',
            "Invalid end time",
        ),
    ],
)
def test_invalid_values_raise_parse_error(xml: str, message: str) -> None:
    with pytest.raises(ParseError, match=message):
        parse_string(xml)


# --- TLS tunnel, detection method and banner ------------------------------------


def test_port_records_tls_tunnel_and_detection_method() -> None:
    port = _only_port(
        '<port protocol="tcp" portid="443"><state state="open"/>'
        '<service name="http" product="nginx" tunnel="ssl" method="probed" conf="10"/></port>'
    )
    assert (port.service_name, port.tunnel, port.method) == ("http", "ssl", "probed")


def test_port_detection_method_from_port_table() -> None:
    port = _only_port(
        '<port protocol="tcp" portid="23"><state state="open"/>'
        '<service name="telnet" method="table" conf="3"/></port>'
    )
    assert (port.tunnel, port.method) == (None, "table")


@pytest.mark.parametrize(
    ("fields", "banner"),
    [
        (
            {"product": "OpenSSH", "version": "8.9p1", "extra_info": "protocol 2.0"},
            "OpenSSH 8.9p1 (protocol 2.0)",
        ),
        ({"product": "Apache httpd"}, "Apache httpd"),
        ({"extra_info": "Ubuntu"}, "(Ubuntu)"),
        ({}, ""),
    ],
)
def test_port_banner(fields: dict[str, str], banner: str) -> None:
    assert Port(port=1, protocol="tcp", state="open", **fields).banner == banner
