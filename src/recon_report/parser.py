"""Convert Nmap XML output into dataclasses.

XML is parsed with defusedxml because scan files may come from untrusted
sources. Its defaults are kept on purpose: a plain ``<!DOCTYPE nmaprun>`` (which
nmap always writes) is allowed, while entity declarations (billion laughs) and
external references (XXE) are rejected.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import defusedxml
import defusedxml.ElementTree as DET

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element

_IP_ADDRESS_TYPES = ("ipv4", "ipv6")


class ParseError(Exception):
    """Raised when a file is not valid, safe Nmap XML."""


@dataclass(frozen=True, slots=True)
class Port:
    """A single port reported for a host.

    ``tunnel`` is ``"ssl"`` when nmap detected the service inside TLS (e.g. HTTPS
    is reported as ``http`` with an ``ssl`` tunnel). ``method`` is ``"probed"``
    when nmap identified the service by probing it, or ``"table"`` when it only
    guessed from the port number.
    """

    port: int
    protocol: str
    state: str
    reason: str | None = None
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    cpes: tuple[str, ...] = ()
    tunnel: str | None = None
    method: str | None = None

    @property
    def banner(self) -> str:
        """Product, version and extra info formatted the way nmap's own output does."""
        text = " ".join(value for value in (self.product, self.version) if value)
        if self.extra_info:
            text = f"{text} ({self.extra_info})" if text else f"({self.extra_info})"
        return text


@dataclass(frozen=True, slots=True)
class Host:
    """A scanned host and the ports nmap reported for it.

    ``extra_ports`` holds nmap's aggregated counts of ports that were not
    listed individually, as ``(state, count)`` pairs, e.g. ``(("filtered", 997),)``.
    """

    address: str
    address_type: str
    status: str
    hostnames: tuple[str, ...] = ()
    ports: tuple[Port, ...] = ()
    extra_ports: tuple[tuple[str, int], ...] = ()

    @property
    def open_ports(self) -> tuple[Port, ...]:
        """Ports whose state is exactly ``open``."""
        return tuple(port for port in self.ports if port.state == "open")


@dataclass(frozen=True, slots=True)
class ScanResult:
    """A parsed Nmap run."""

    nmap_version: str | None
    args: str | None
    start_time: datetime | None
    end_time: datetime | None
    hosts: tuple[Host, ...] = ()

    @property
    def hosts_up(self) -> tuple[Host, ...]:
        """Hosts whose status is ``up``."""
        return tuple(host for host in self.hosts if host.status == "up")


def parse_file(path: Path) -> ScanResult:
    """Parse an Nmap XML file produced by ``nmap -oX``.

    Raises:
        ParseError: If the file cannot be read or is not valid, safe Nmap XML.
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ParseError(f"Cannot read {path}: {exc.strerror or exc}") from exc
    return parse_string(data, source=str(path))


def parse_string(data: str | bytes, source: str = "<string>") -> ScanResult:
    """Parse Nmap XML from a string or bytes.

    Args:
        data: The XML document.
        source: Name used in error messages, e.g. the file path.

    Raises:
        ParseError: If the data is malformed, unsafe, or not Nmap XML.
    """
    try:
        root = DET.fromstring(data)
    except DET.ParseError as exc:
        raise ParseError(f"{source} is not well-formed XML: {exc}") from exc
    except defusedxml.DefusedXmlException as exc:
        raise ParseError(f"{source} was rejected as unsafe XML: {exc}") from exc

    if root.tag != "nmaprun":
        raise ParseError(f"{source} is not Nmap XML: root element is <{root.tag}>, not <nmaprun>.")

    finished = root.find("runstats/finished")
    return ScanResult(
        nmap_version=_text_attr(root, "version"),
        args=_text_attr(root, "args"),
        start_time=_timestamp(root.get("start"), "start time"),
        end_time=_timestamp(finished.get("time") if finished is not None else None, "end time"),
        hosts=tuple(_parse_host(host) for host in root.findall("host")),
    )


def _parse_host(element: Element) -> Host:
    addresses = [
        (addr.get("addr"), addr.get("addrtype", "unknown"))
        for addr in element.findall("address")
        if addr.get("addr")
    ]
    if not addresses:
        raise ParseError("Host element has no address.")
    address, address_type = next(
        (pair for pair in addresses if pair[1] in _IP_ADDRESS_TYPES), addresses[0]
    )

    status = element.find("status")
    hostnames = dict.fromkeys(
        name.get("name") for name in element.findall("hostnames/hostname") if name.get("name")
    )
    extra_ports = tuple(
        (extra.get("state", "unknown"), _int(extra.get("count"), "extraports count"))
        for extra in element.findall("ports/extraports")
    )

    return Host(
        address=address,
        address_type=address_type,
        status=status.get("state", "unknown") if status is not None else "unknown",
        hostnames=tuple(hostnames),
        ports=tuple(_parse_port(port) for port in element.findall("ports/port")),
        extra_ports=extra_ports,
    )


def _parse_port(element: Element) -> Port:
    protocol = element.get("protocol")
    if not protocol:
        raise ParseError("Port element has no protocol.")

    state = element.find("state")
    service = element.find("service")
    if service is None:
        service_fields: dict[str, str | None] = {}
        cpes: tuple[str, ...] = ()
    else:
        service_fields = {
            "service_name": _text_attr(service, "name"),
            "product": _text_attr(service, "product"),
            "version": _text_attr(service, "version"),
            "extra_info": _text_attr(service, "extrainfo"),
            "tunnel": _text_attr(service, "tunnel"),
            "method": _text_attr(service, "method"),
        }
        cpes = tuple(cpe.text.strip() for cpe in service.findall("cpe") if (cpe.text or "").strip())

    return Port(
        port=_int(element.get("portid"), "portid"),
        protocol=protocol,
        state=state.get("state", "unknown") if state is not None else "unknown",
        reason=_text_attr(state, "reason") if state is not None else None,
        cpes=cpes,
        **service_fields,
    )


def _text_attr(element: Element, name: str) -> str | None:
    """Return an attribute value, treating missing and blank values as ``None``."""
    value = element.get(name)
    return value if value and value.strip() else None


def _int(value: str | None, field: str) -> int:
    if value is None:
        raise ParseError(f"Missing required {field}.")
    try:
        return int(value)
    except ValueError as exc:
        raise ParseError(f"Invalid {field}: {value!r} is not an integer.") from exc


def _timestamp(value: str | None, field: str) -> datetime | None:
    if not value:
        return None
    seconds = _int(value, field)
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise ParseError(f"Invalid {field}: {value!r} is out of range.") from exc
