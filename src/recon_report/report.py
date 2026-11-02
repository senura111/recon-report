"""Render a scan and its risk assessment as HTML and Markdown reports.

All scan data (hostnames, banners, versions, evidence, the nmap command line) is
untrusted, so both formats escape every value by default:

- HTML uses Jinja2 autoescaping. The page is a single self-contained file with
  inline CSS, no JavaScript and no external resources, and a Content-Security-Policy
  that allows only the inlined stylesheet (by hash) as defense in depth.
- Markdown runs every ``{{ ... }}`` output through :func:`escape_markdown` via the
  environment's ``finalize`` hook, so a template cannot forget to escape a value.
  Only :class:`TrustedMarkdown` values, built by this module, are output as is.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from importlib import resources
from pathlib import Path

from jinja2 import Environment, PackageLoader, StrictUndefined
from markupsafe import Markup

from recon_report import __version__, filenames
from recon_report.parser import Host, Port, ScanResult
from recon_report.risk import (
    BACKPORT_NOTE,
    SERVICE_RULES,
    VERSION_RULES,
    Assessment,
    Confidence,
    Finding,
    Severity,
    assess,
)

MAX_TARGETS_SHOWN = 10
"""Hosts listed by name in the report header; the rest are summarized as "and N more"."""

CONFIDENCE_NOTES = {
    Confidence.CONFIRMED: "nmap identified the service by probing it",
    Confidence.LIKELY: "nmap guessed the service from the port number only",
    Confidence.POTENTIAL: "based on the banner version, which may not reflect patch status",
}

_TEMPLATES = "templates"
_UNKNOWN = "Unknown"
_HTTPS_URL = re.compile(r"https://[^\s<>\"'`\\]+")
# Every ASCII punctuation character CommonMark allows to be backslash-escaped.
_MARKDOWN_SPECIAL = re.compile(r"""([!"#$%&'()*+,\-./:;<=>?@\[\\\]^_`{|}~])""")
# Line breaks and other control characters would end a table row or start a new block.
_MARKDOWN_BREAKS = re.compile(r"[\x00-\x1f\x7f\x85  ]+")
_DETECTION_LABELS = {"probed": "Probed", "table": "Port number only"}


class ReportError(Exception):
    """Raised when a report cannot be written."""


class ReportFormat(str, Enum):
    """Report output format."""

    HTML = "html"
    MD = "md"
    BOTH = "both"

    @property
    def extensions(self) -> tuple[str, ...]:
        """File extensions written for this format, e.g. ``("html", "md")`` for ``both``."""
        return ("html", "md") if self is ReportFormat.BOTH else (self.value,)


class TrustedMarkdown(str):
    """Markdown produced by this module that must not be escaped again."""


@dataclass(frozen=True, slots=True)
class PortRow:
    """One open port as shown in a host's port table."""

    port: str
    service: str
    version: str
    detection: str


@dataclass(frozen=True, slots=True)
class HostSection:
    """A host and its open ports, ready to render.

    ``not_shown`` summarizes ports nmap reported but that are not open, e.g.
    ``"Not shown: 997 filtered ports."``.
    """

    address: str
    hostnames: tuple[str, ...]
    status: str
    ports: tuple[PortRow, ...] = ()
    not_shown: str | None = None

    @property
    def label(self) -> str:
        """Address followed by hostnames, e.g. ``"45.33.32.156 (scanme.nmap.org)"``."""
        return _host_label(self.address, self.hostnames)


@dataclass(frozen=True, slots=True)
class SeverityCount:
    """Number of findings at one severity."""

    severity: Severity
    count: int


@dataclass(frozen=True, slots=True)
class ReportContext:
    """Everything the report templates display, computed once for both formats.

    All strings are plain text; the templates escape them for their format.
    """

    label: str
    notice: str | None
    targets: tuple[str, ...]
    targets_more: int
    scan_started: str
    scan_finished: str
    duration: str
    nmap_version: str
    nmap_command: str
    scan_method: str
    tool_version: str
    generated_at: str
    counts: tuple[SeverityCount, ...]
    summary: str
    hosts_up: tuple[HostSection, ...]
    hosts_not_up: tuple[HostSection, ...]
    findings: tuple[Finding, ...]
    service_rule_count: int
    version_rule_count: int
    rules_last_reviewed: str
    backport_note: str

    @property
    def targets_text(self) -> str:
        """The targets as one line, e.g. ``"10.0.0.3, 10.0.0.20 and 4 more"``."""
        if not self.targets:
            return "No hosts reported"
        text = ", ".join(self.targets)
        return f"{text} and {self.targets_more} more" if self.targets_more else text


def build_context(
    result: ScanResult,
    assessment: Assessment | None = None,
    *,
    generated_at: datetime | None = None,
    notice: str | None = None,
) -> ReportContext:
    """Collect the values shown in a report.

    Args:
        result: Parsed scan result.
        assessment: Risk assessment of ``result``; computed with the default rules if omitted.
        generated_at: Report generation time (UTC); defaults to now.
        notice: Optional note shown prominently under the title, e.g. that the data is
            fictional.
    """
    if assessment is None:
        assessment = assess(result)
    labels = tuple(_host_label(host.address, host.hostnames) for host in result.hosts)
    reviewed = min((rule.last_reviewed for rule in VERSION_RULES), default=None)
    return ReportContext(
        label=_report_label(result),
        notice=notice,
        targets=labels[:MAX_TARGETS_SHOWN],
        targets_more=max(len(labels) - MAX_TARGETS_SHOWN, 0),
        scan_started=_format_time(result.start_time),
        scan_finished=_format_time(result.end_time),
        duration=_duration(result),
        nmap_version=result.nmap_version or _UNKNOWN,
        nmap_command=result.args or _UNKNOWN,
        scan_method=_scan_method(result.args),
        tool_version=__version__,
        generated_at=_format_time(generated_at or datetime.now(timezone.utc)),
        counts=tuple(SeverityCount(sev, count) for sev, count in assessment.counts.items()),
        summary=summary_sentence(result, assessment),
        hosts_up=tuple(_host_section(host) for host in result.hosts if host.status == "up"),
        hosts_not_up=tuple(
            HostSection(host.address, host.hostnames, host.status)
            for host in result.hosts
            if host.status != "up"
        ),
        findings=assessment.findings,
        service_rule_count=len(SERVICE_RULES),
        version_rule_count=len(VERSION_RULES),
        rules_last_reviewed=reviewed.isoformat() if reviewed else _UNKNOWN,
        backport_note=BACKPORT_NOTE,
    )


def render_html(
    result: ScanResult,
    assessment: Assessment | None = None,
    *,
    generated_at: datetime | None = None,
    notice: str | None = None,
) -> str:
    """Render a self-contained HTML report. See :func:`build_context` for the arguments."""
    context = build_context(result, assessment, generated_at=generated_at, notice=notice)
    css = _stylesheet()
    return (
        _html_env()
        .get_template("report.html.j2")
        .render(
            ctx=context,
            css=Markup(css),
            csp=content_security_policy(css),
            confidence_notes=CONFIDENCE_NOTES,
        )
    )


def render_markdown(
    result: ScanResult,
    assessment: Assessment | None = None,
    *,
    generated_at: datetime | None = None,
    notice: str | None = None,
) -> str:
    """Render a GitHub-flavoured Markdown report. See :func:`build_context` for the arguments."""
    context = build_context(result, assessment, generated_at=generated_at, notice=notice)
    return (
        _markdown_env()
        .get_template("report.md.j2")
        .render(ctx=context, confidence_notes=CONFIDENCE_NOTES)
    )


def write_reports(
    result: ScanResult,
    assessment: Assessment,
    output_dir: Path,
    fmt: ReportFormat = ReportFormat.HTML,
    *,
    now: datetime | None = None,
    notice: str | None = None,
) -> list[Path]:
    """Render reports and write them to ``output_dir`` with timestamped filenames.

    Files are named ``report_<label>_<timestamp>.<ext>``, where the label is the
    single host's hostname or address, or ``<N>-hosts``. Existing files are never
    overwritten: a ``-1``, ``-2``... suffix is added instead, shared by all formats
    written in one call.

    Returns:
        The paths written, HTML first.

    Raises:
        ReportError: If the directory or a file cannot be written.
    """
    now = now or datetime.now(timezone.utc)
    renderers = {"html": render_html, "md": render_markdown}
    contents = {
        ext: renderers[ext](result, assessment, generated_at=now, notice=notice)
        for ext in fmt.extensions
    }
    base = f"report_{filenames.safe_part(_filename_label(result))}_{filenames.timestamp(now)}"
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        stem = _free_stem(output_dir, base, fmt.extensions)
        paths = []
        for ext, content in contents.items():
            path = output_dir / f"{stem}.{ext}"
            # "x" fails rather than overwrite a file created since the check above.
            with path.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
            paths.append(path)
    except OSError as exc:
        raise ReportError(f"Cannot write report to {output_dir}: {exc.strerror or exc}") from exc
    return paths


def escape_markdown(value: object) -> str:
    """Escape text so Markdown renders it literally, on one line.

    Every ASCII punctuation character is backslash-escaped, so the text cannot start
    emphasis, code spans, links, images, raw HTML, entities, math or strikethrough,
    or split a table cell. Line breaks and other control characters become spaces,
    so the text cannot end a table row or start a new block.
    """
    text = _MARKDOWN_BREAKS.sub(" ", str(value))
    return _MARKDOWN_SPECIAL.sub(r"\\\1", text)


def content_security_policy(css: str) -> str:
    """Return a CSP that allows only the given inline stylesheet, by SHA-256 hash."""
    digest = base64.b64encode(hashlib.sha256(css.encode("utf-8")).digest()).decode("ascii")
    return f"default-src 'none'; style-src 'sha256-{digest}'; base-uri 'none'; form-action 'none'"


def summary_sentence(result: ScanResult, assessment: Assessment) -> str:
    """Describe the scan outcome in one or two plain-text sentences."""
    total = len(result.hosts)
    if total == 0:
        return "The scan did not report any hosts, so no services were assessed."
    up = len(result.hosts_up)
    if up == 0:
        return f"No hosts were up ({_count(total, 'host')} reported), so no services were assessed."

    open_ports = sum(len(host.open_ports) for host in result.hosts_up)
    scanned = (
        f"{up} of {_count(total, 'host')} {_was(up)} up, with {_count(open_ports, 'open port')}."
    )
    findings = assessment.findings
    if not findings:
        return (
            f"{scanned} No findings were identified by the current rules; this does not "
            "prove the hosts are free of vulnerabilities."
        )

    counts = _join_and([f"{n} {sev.label}" for sev, n in assessment.counts.items() if n])
    top = findings[0]
    host = _host_label(top.host, (top.hostname,) if top.hostname else ())
    where = f"{host}, port {top.port}/{top.protocol}"
    top_count = assessment.counts[top.severity]
    if top_count == 1:
        most_severe = f"The most severe finding is {top.title} ({top.severity.label}) on {where}."
    else:
        most_severe = (
            f"The most severe findings are rated {top.severity.label}, "
            f"starting with {top.title} on {where}."
        )
    return (
        f"{scanned} {_count(len(findings), 'finding')} {_was(len(findings))} identified "
        f"({counts}). {most_severe}"
    )


def not_shown_line(host: Host) -> str | None:
    """Summarize the host's ports that are not open, e.g. ``"Not shown: 997 filtered ports."``.

    Combines nmap's aggregated ``extraports`` counts with individually listed
    ports whose state is not ``open``. Returns ``None`` when there are none.
    """
    counts: dict[str, int] = {}
    for state, count in host.extra_ports:
        counts[state] = counts.get(state, 0) + count
    for port in host.ports:
        if port.state != "open":
            counts[port.state] = counts.get(port.state, 0) + 1
    parts = [_count(count, f"{state} port") for state, count in counts.items() if count]
    return f"Not shown: {', '.join(parts)}." if parts else None


def _host_section(host: Host) -> HostSection:
    return HostSection(
        address=host.address,
        hostnames=host.hostnames,
        status=host.status,
        ports=tuple(_port_row(port) for port in host.open_ports),
        not_shown=not_shown_line(host),
    )


def _port_row(port: Port) -> PortRow:
    service = port.service_name or "unknown"
    if port.tunnel == "ssl":
        service = f"ssl/{service}"
    return PortRow(
        port=f"{port.port}/{port.protocol}",
        service=service,
        version=port.banner,
        detection=_DETECTION_LABELS.get(port.method or "", _UNKNOWN),
    )


def _host_label(address: str, hostnames: Sequence[str]) -> str:
    return f"{address} ({', '.join(hostnames)})" if hostnames else address


def _report_label(result: ScanResult) -> str:
    if not result.hosts:
        return "No hosts"
    if len(result.hosts) == 1:
        host = result.hosts[0]
        return _host_label(host.address, host.hostnames)
    return f"{len(result.hosts)} hosts"


def _filename_label(result: ScanResult) -> str:
    if not result.hosts:
        return "no-hosts"
    if len(result.hosts) == 1:
        host = result.hosts[0]
        return host.hostnames[0] if host.hostnames else host.address
    return f"{len(result.hosts)}-hosts"


def _scan_method(args: str | None) -> str:
    if args is None:
        return (
            "The XML file does not record the Nmap command line, so the scan options are unknown."
        )
    if {"-sV", "-A"} & set(args.split()):
        return (
            "Nmap service version detection (-sV) probed each open port and identified the "
            "product and version from the service's responses."
        )
    return (
        "The Nmap command does not include service version detection (-sV), so service "
        "names were inferred from port numbers and no version-based findings were possible."
    )


def _format_time(value: datetime | None) -> str:
    if value is None:
        return _UNKNOWN
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _duration(result: ScanResult) -> str:
    if result.start_time is None or result.end_time is None:
        return _UNKNOWN
    seconds = max(int((result.end_time - result.start_time).total_seconds()), 0)
    hours, rest = divmod(seconds, 3600)
    minutes, seconds = divmod(rest, 60)
    if hours:
        return f"{hours}h {minutes}m {seconds}s"
    return f"{minutes}m {seconds}s" if minutes else f"{seconds}s"


def _count(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _was(count: int) -> str:
    return "was" if count == 1 else "were"


def _join_and(items: Iterable[str]) -> str:
    items = list(items)
    if len(items) <= 1:
        return "".join(items)
    return f"{', '.join(items[:-1])} and {items[-1]}"


def _free_stem(directory: Path, base: str, extensions: Sequence[str]) -> str:
    for attempt in range(1000):
        stem = f"{base}-{attempt}" if attempt else base
        if not any((directory / f"{stem}.{ext}").exists() for ext in extensions):
            return stem
    raise ReportError(f"Too many reports named {base} in {directory}.")


def _is_https_url(value: object) -> bool:
    return isinstance(value, str) and _HTTPS_URL.fullmatch(value) is not None


def _markdown_link(url: str) -> TrustedMarkdown:
    """Render a reference as an autolink if it is a plain HTTPS URL, else as escaped text."""
    return TrustedMarkdown(f"<{url}>" if _is_https_url(url) else escape_markdown(url))


def _markdown_finalize(value: object) -> str:
    return value if isinstance(value, TrustedMarkdown) else escape_markdown(value)


@functools.cache
def _stylesheet() -> str:
    css = resources.files("recon_report").joinpath(_TEMPLATES, "report.css").read_text("utf-8")
    if "</" in css:
        raise ReportError("report.css must not contain '</', which could close the style element.")
    return css


@functools.cache
def _html_env() -> Environment:
    env = Environment(
        loader=PackageLoader("recon_report", _TEMPLATES),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.tests["https_url"] = _is_https_url
    return env


@functools.cache
def _markdown_env() -> Environment:
    env = Environment(
        loader=PackageLoader("recon_report", _TEMPLATES),
        autoescape=False,
        finalize=_markdown_finalize,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["md_link"] = _markdown_link
    return env
