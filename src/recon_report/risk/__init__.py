"""Severity rules for discovered services and versions.

- :mod:`.models`: severity, confidence, finding and rule types
- :mod:`.rules`: the rule definitions (data only)
- :mod:`.engine`: evaluates a parsed scan against the rules
"""

from __future__ import annotations

from recon_report.risk.engine import (
    BACKPORT_NOTE,
    Assessment,
    assess,
    compare_versions,
    parse_version,
    severity_counts,
)
from recon_report.risk.models import Confidence, Finding, ServiceRule, Severity, VersionRule
from recon_report.risk.rules import SERVICE_RULES, VERSION_RULES

__all__ = [
    "BACKPORT_NOTE",
    "SERVICE_RULES",
    "VERSION_RULES",
    "Assessment",
    "Confidence",
    "Finding",
    "ServiceRule",
    "Severity",
    "VersionRule",
    "assess",
    "compare_versions",
    "parse_version",
    "severity_counts",
]
