"""Severity rules for discovered services and versions.

Not implemented yet.
"""

from __future__ import annotations


def assess(scan_result: object) -> object:
    """Assign severity ratings to the services in a parsed scan result.

    Args:
        scan_result: Parsed scan result from :mod:`recon_report.parser`.

    Raises:
        NotImplementedError: Always, until risk rules are implemented.
    """
    raise NotImplementedError("risk assessment is not implemented yet")
