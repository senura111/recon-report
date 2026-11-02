"""Convert Nmap XML output into dataclasses.

Not implemented yet.
"""

from __future__ import annotations

from pathlib import Path


def parse_nmap_xml(xml_path: Path) -> object:
    """Parse an Nmap XML file into structured scan results.

    Args:
        xml_path: Path to an XML file produced by ``nmap -oX``.

    Raises:
        NotImplementedError: Always, until the parser is implemented.
    """
    raise NotImplementedError("parser is not implemented yet")
