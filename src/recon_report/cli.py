"""Command-line entry point for recon-report."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from recon_report import __version__, scanner

app = typer.Typer(
    help="Defensive reconnaissance and reporting for authorized penetration testing.",
    no_args_is_help=True,
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"recon-report {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
        ),
    ] = False,
) -> None:
    """Scan only systems you own or are explicitly authorized to test."""


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="Single IP address or hostname to scan.")],
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Directory to save the Nmap XML output in."),
    ] = Path("scans"),
    ports: Annotated[
        str | None,
        typer.Option("--ports", "-p", help="Port specification, e.g. 22,80,443 or 1-1024."),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option("--timeout", "-t", help="Maximum scan duration in seconds."),
    ] = scanner.DEFAULT_TIMEOUT_SECONDS,
) -> None:
    """Run an Nmap service version scan (-sV) and save the XML output."""
    typer.echo(f"Scanning {target} ...")
    try:
        xml_path = scanner.run_scan(target, output, ports=ports, timeout=timeout)
    except scanner.InvalidTargetError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except scanner.ScanError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Scan complete. XML saved to {xml_path}")
