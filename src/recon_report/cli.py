"""Command-line entry point for recon-report."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from recon_report import __version__, parser, scanner

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
    """Run an Nmap service version scan (-sV), save the XML output and print a summary."""
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
    _print_summary(_load(xml_path))


@app.command("parse")
def parse_command(
    xml_file: Annotated[
        Path,
        typer.Argument(
            help="Nmap XML file to summarize.", exists=True, dir_okay=False, readable=True
        ),
    ],
) -> None:
    """Print a summary table of hosts and open ports from an Nmap XML file."""
    _print_summary(_load(xml_file))


def _load(xml_path: Path) -> parser.ScanResult:
    try:
        return parser.parse_file(xml_path)
    except parser.ParseError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


def _print_summary(result: parser.ScanResult) -> None:
    """Print a run header and a table of each host's open ports."""
    console = Console()
    console.print(Text(_summary_header(result)))
    if not result.hosts:
        console.print("No hosts found in scan.")
        return

    table = Table(title="Hosts and open ports", title_justify="left")
    for column in ("Host", "Port", "State", "Service", "Version"):
        table.add_column(column)

    for index, host in enumerate(result.hosts):
        if index:
            table.add_section()
        label = Text(host.address)
        if host.hostnames:
            label.append(f" ({', '.join(host.hostnames)})", style="dim")

        if host.status != "up":
            table.add_row(label, "-", Text(host.status, style="red"), "", "")
        elif not host.open_ports:
            table.add_row(label, "-", "up", Text("no open ports", style="dim"), "")
        for port in host.open_ports:
            # Values come from untrusted XML, so wrap them in Text to avoid rich markup.
            table.add_row(
                label,
                Text(f"{port.port}/{port.protocol}"),
                Text(port.state, style="green"),
                Text(port.service_name or "unknown"),
                Text(_version_string(port)),
            )
            label = Text("")

    console.print(table)


def _summary_header(result: parser.ScanResult) -> str:
    parts = [f"Nmap {result.nmap_version or 'unknown version'}"]
    if result.start_time:
        parts.append(f"started {result.start_time:%Y-%m-%d %H:%M:%S} UTC")
    if result.start_time and result.end_time:
        parts.append(f"took {(result.end_time - result.start_time).total_seconds():.0f}s")
    parts.append(f"{len(result.hosts_up)}/{len(result.hosts)} hosts up")
    return ", ".join(parts)


def _version_string(port: parser.Port) -> str:
    """Format product, version and extra info the way nmap's own output does."""
    text = " ".join(value for value in (port.product, port.version) if value)
    if port.extra_info:
        text = f"{text} ({port.extra_info})" if text else f"({port.extra_info})"
    return text
