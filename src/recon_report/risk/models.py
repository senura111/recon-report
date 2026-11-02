"""Data types shared by the risk rules and the evaluation engine."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import Enum, IntEnum


class Severity(IntEnum):
    """Finding severity. Higher values are more severe, so severities compare and sort."""

    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @property
    def label(self) -> str:
        """Display name, e.g. ``"High"``."""
        return self.name.capitalize()

    def __str__(self) -> str:
        return self.label

    @classmethod
    def parse(cls, value: str) -> Severity:
        """Parse a severity name case-insensitively, e.g. ``"high"`` or ``"High"``.

        Raises:
            ValueError: If ``value`` is not a severity name.
        """
        try:
            return cls[value.strip().upper()]
        except KeyError:
            choices = ", ".join(severity.label for severity in cls)
            raise ValueError(f"Unknown severity {value!r}; expected one of: {choices}.") from None


class Confidence(str, Enum):
    """How sure a finding is.

    ``confirmed``: nmap identified the service by probing it.
    ``likely``: nmap only guessed the service from the port number.
    ``potential``: inferred from a banner version, which may not reflect patch status.
    """

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POTENTIAL = "potential"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class Finding:
    """A single issue found on a host's open port."""

    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    host: str
    port: int
    protocol: str
    evidence: str
    description: str
    recommendation: str
    hostname: str | None = None
    references: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ServiceRule:
    """Flags an exposed service, identified by nmap service name or product.

    Attributes:
        services: nmap service names to match exactly, case-insensitively (e.g. ``"telnet"``).
        products: Case-insensitive substrings of nmap's product string
            (e.g. ``"Elasticsearch"``), for services nmap reports under a generic
            name such as ``http``.
        tls: ``False`` matches only cleartext services, ``True`` only TLS-tunnelled
            ones, ``None`` either.
        fallback: A fallback rule only fires when no non-fallback rule matched the
            same port, so a generic rule (cleartext HTTP) does not duplicate a
            specific one (an HTTP-based database API).
    """

    rule_id: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    services: tuple[str, ...] = ()
    products: tuple[str, ...] = ()
    tls: bool | None = None
    fallback: bool = False
    references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not (self.services or self.products):
            raise ValueError(f"Rule {self.rule_id} must match at least one service or product.")


@dataclass(frozen=True, slots=True)
class VersionRule:
    """Flags a product whose banner version is outdated or known to be vulnerable.

    Findings from version rules always have ``potential`` confidence.

    Attributes:
        products: nmap product names to match exactly, case-insensitively
            (e.g. ``"OpenSSH"``, ``"Apache httpd"``).
        last_reviewed: When the thresholds were last checked against the vendor's
            official lifecycle or advisory pages.
        below: Flag versions strictly lower than this one.
        versions: Flag these exact versions. Set either ``below`` or ``versions``.
        exclude: Case-insensitive substrings of the banner that rule a match out
            (e.g. ``"MariaDB"``, whose banners imitate old MySQL versions).
    """

    rule_id: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    products: tuple[str, ...]
    last_reviewed: date
    below: str | None = None
    versions: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (self.below is None) == (not self.versions):
            raise ValueError(f"Rule {self.rule_id} must set exactly one of below or versions.")
