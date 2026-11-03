"""Tests for recon_report.report using XML fixtures. nmap is never executed."""

from __future__ import annotations

import base64
import hashlib
import html
import importlib.util
import re
import string
import sys
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from importlib import resources
from pathlib import Path
from xml.sax.saxutils import quoteattr

import pytest
from markdown_it import MarkdownIt
from markupsafe import escape

from recon_report import __version__, filenames, report
from recon_report.parser import Host, Port, ScanResult, parse_file
from recon_report.report import ReportFormat
from recon_report.risk import SERVICE_RULES, VERSION_RULES, assess

ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 11, 3, 9, 30, 15, tzinfo=timezone.utc)
RULE_REFERENCES = {ref for rule in (*SERVICE_RULES, *VERSION_RULES) for ref in rule.references}

# Untrusted values with HTML, Markdown and table-breaking content.
EVIL_HOSTNAME = '<script>alert("host")</script>'
EVIL_PRODUCT = '<img src=x onerror=alert(1)> " onmouseover="alert(2)'
EVIL_VERSION = "1.0 | injected | cell"
EVIL_EXTRA = "`code` *bold* _it_ [link](javascript:alert(3)) ![i](https://x.test/i.png) $x$ ~~s~~"
EVIL_EXTRA_MULTILINE = EVIL_EXTRA + "\n### heading &amp; <b>raw</b>\n| a | b |"
EVIL_BANNER = f"{EVIL_PRODUCT} {EVIL_VERSION} ({EVIL_EXTRA_MULTILINE})"
# Markdown output puts every value on one line.
EVIL_BANNER_ONE_LINE = EVIL_BANNER.replace("\n", " ")


def _scan(*hosts: Host, args: str | None = "nmap -sV 10.0.0.5") -> ScanResult:
    start = datetime(2026, 11, 2, 12, 0, 0, tzinfo=timezone.utc)
    return ScanResult(
        nmap_version="7.95",
        args=args,
        start_time=start,
        end_time=start + timedelta(seconds=42),
        hosts=hosts,
    )


def _host(address: str = "10.0.0.5", *ports: Port, status: str = "up", **fields) -> Host:
    return Host(address=address, address_type="ipv4", status=status, ports=ports, **fields)


def _port(port: int, service: str, **fields: str) -> Port:
    fields.setdefault("method", "probed")
    return Port(port=port, protocol="tcp", state="open", service_name=service, **fields)


@pytest.fixture(scope="module")
def scanme() -> ScanResult:
    return parse_file(FIXTURES / "single_host.xml")


@pytest.fixture(scope="module")
def risky() -> ScanResult:
    return parse_file(FIXTURES / "risky_host.xml")


@pytest.fixture
def evil(tmp_path: Path) -> ScanResult:
    """A scan whose hostname and banner contain HTML and Markdown injection attempts."""
    xml = tmp_path / "evil.xml"
    xml.write_text(
        '<nmaprun version="7.95" args="nmap -sV 10.0.0.66"><host><status state="up"/>'
        '<address addr="10.0.0.66" addrtype="ipv4"/>'
        f"<hostnames><hostname name={quoteattr(EVIL_HOSTNAME)}/></hostnames><ports>"
        '<port protocol="tcp" portid="23"><state state="open"/>'
        f'<service name="telnet" method="probed" product={quoteattr(EVIL_PRODUCT)} '
        f"version={quoteattr(EVIL_VERSION)} extrainfo={quoteattr(EVIL_EXTRA_MULTILINE)}/>"
        "</port></ports></host></nmaprun>",
        encoding="utf-8",
    )
    return parse_file(xml)


class _HTMLCollector(HTMLParser):
    """Collects tags, attributes and text content of an HTML document."""

    def __init__(self, document: str) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.attrs: list[tuple[str, str | None]] = []
        self.cells: list[str] = []
        self._text: list[str] = []
        self._cell: list[str] | None = None
        self.feed(document)
        self.close()

    @property
    def text(self) -> str:
        return "".join(self._text)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attrs.extend(attrs)
        if tag == "td":
            self._cell = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "td" and self._cell is not None:
            self.cells.append("".join(self._cell))
            self._cell = None

    def handle_data(self, data: str) -> None:
        self._text.append(data)
        if self._cell is not None:
            self._cell.append(data)


def _markdown_to_html(text: str) -> str:
    """Render Markdown like GitHub does for this report: CommonMark, tables, raw HTML."""
    return MarkdownIt("commonmark", {"html": True}).enable(["table", "strikethrough"]).render(text)


def _unescaped(text: str) -> str:
    """Drop backslash-escaped characters, leaving only characters Markdown treats as syntax."""
    return re.sub(r"\\.", "", text)


# --- escape_markdown ----------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("plain text 123", "plain text 123"),
        ("a|b", r"a\|b"),
        ("`code`", r"\`code\`"),
        ("<script>", r"\<script\>"),
        ("*bold* _it_", r"\*bold\* \_it\_"),
        ("[x](javascript:y)", r"\[x\]\(javascript\:y\)"),
        ("$math$ ~~s~~ &amp;", r"\$math\$ \~\~s\~\~ \&amp\;"),
        ("back\\slash", r"back\\slash"),
        ("line1\nline2\r\n\tline3", "line1 line2 line3"),
        ("a b\x00c", "a b c"),
        ("café — 東京", "café — 東京"),
    ],
)
def test_escape_markdown(value: str, expected: str) -> None:
    assert report.escape_markdown(value) == expected


def test_escape_markdown_escapes_every_ascii_punctuation_character() -> None:
    for char in string.punctuation:
        assert report.escape_markdown(char) == "\\" + char


# --- context ------------------------------------------------------------------


def test_not_shown_line_combines_extraports_and_listed_ports() -> None:
    hosts = parse_file(FIXTURES / "multi_host.xml").hosts
    assert report.not_shown_line(hosts[0]) == "Not shown: 994 closed ports, 3 filtered ports."
    assert report.not_shown_line(hosts[1]) == "Not shown: 997 filtered ports."


def test_not_shown_line_singular_and_none(scanme: ScanResult, risky: ScanResult) -> None:
    assert report.not_shown_line(scanme.hosts[0]) is None
    assert report.not_shown_line(risky.hosts[0]) == "Not shown: 1 closed port."


def test_summary_sentence_scanme(scanme: ScanResult) -> None:
    assert report.summary_sentence(scanme, assess(scanme)) == (
        "1 of 1 host was up, with 2 open ports. 2 findings were identified "
        "(1 Medium and 1 Low). The most severe finding is Outdated OpenSSH version "
        "(Medium) on 45.33.32.156 (scanme.nmap.org), port 22/tcp."
    )


def test_summary_sentence_risky_host(risky: ScanResult) -> None:
    assert report.summary_sentence(risky, assess(risky)) == (
        "2 of 3 hosts were up, with 10 open ports. 10 findings were identified "
        "(1 Critical, 6 High, 2 Medium and 1 Low). The most severe finding is Docker Engine "
        "API exposed without TLS (Critical) on 10.0.0.20 (lab-app.internal), port 2375/tcp."
    )


def test_summary_sentence_several_findings_at_top_severity() -> None:
    result = _scan(_host("10.0.0.5", _port(23, "telnet")), _host("10.0.0.6", _port(23, "telnet")))
    assert report.summary_sentence(result, assess(result)).endswith(
        "2 findings were identified (2 High). The most severe findings are rated High, "
        "starting with Telnet service exposed on 10.0.0.5, port 23/tcp."
    )


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (_scan(), "The scan did not report any hosts, so no services were assessed."),
        (
            _scan(_host(status="down")),
            "No hosts were up (1 host reported), so no services were assessed.",
        ),
        (
            _scan(_host("10.0.0.5", _port(22, "ssh", product="OpenSSH", version="9.6"))),
            "1 of 1 host was up, with 1 open port. No findings were identified by the current "
            "rules; this does not prove the hosts are free of vulnerabilities.",
        ),
    ],
)
def test_summary_sentence_without_findings(result: ScanResult, expected: str) -> None:
    assert report.summary_sentence(result, assess(result)) == expected


def test_build_context_scanme(scanme: ScanResult) -> None:
    context = report.build_context(scanme, generated_at=NOW)
    assert context.label == "45.33.32.156 (scanme.nmap.org)"
    assert context.targets == ("45.33.32.156 (scanme.nmap.org)",)
    assert context.scan_started == "2026-11-02 18:09:13 UTC"
    assert context.scan_finished == "2026-11-02 18:09:24 UTC"
    assert context.duration == "11s"
    assert context.nmap_version == "7.993"
    assert context.nmap_command == scanme.args
    assert context.generated_at == "2026-11-03 09:30:15 UTC"
    assert context.tool_version == __version__
    assert [(c.severity.label, c.count) for c in context.counts] == [
        ("Critical", 0),
        ("High", 0),
        ("Medium", 1),
        ("Low", 1),
        ("Info", 0),
    ]
    port_rows = context.hosts_up[0].ports
    assert [(row.port, row.service, row.detection) for row in port_rows] == [
        ("22/tcp", "ssh", "Probed"),
        ("80/tcp", "http", "Probed"),
    ]
    assert context.rules_last_reviewed == min(r.last_reviewed for r in VERSION_RULES).isoformat()


def test_build_context_port_rows_show_tls_and_guessed_services(risky: ScanResult) -> None:
    rows = {row.port: row for row in report.build_context(risky).hosts_up[0].ports}
    assert rows["443/tcp"].service == "ssl/http"
    assert rows["3389/tcp"].detection == "Port number only"
    assert rows["3389/tcp"].version == ""
    assert "21/tcp" not in rows


def test_build_context_separates_hosts_not_up(risky: ScanResult) -> None:
    context = report.build_context(risky)
    assert [host.address for host in context.hosts_up] == ["10.0.0.20", "10.0.0.3"]
    assert [(host.label, host.status) for host in context.hosts_not_up] == [("10.0.0.100", "down")]
    assert context.hosts_not_up[0].ports == ()
    assert context.duration == "1m 0s"


def test_build_context_limits_targets_listed() -> None:
    hosts = [_host(f"10.0.0.{i}") for i in range(1, 13)]
    context = report.build_context(_scan(*hosts))
    assert len(context.targets) == report.MAX_TARGETS_SHOWN
    assert context.targets_more == 2
    assert context.targets_text.endswith("10.0.0.10 and 2 more")
    assert context.label == "12 hosts"


def test_build_context_unknown_values() -> None:
    result = ScanResult(nmap_version=None, args=None, start_time=None, end_time=None)
    context = report.build_context(result)
    assert context.label == "No hosts"
    assert context.targets_text == "No hosts reported"
    assert (context.scan_started, context.duration, context.nmap_version) == ("Unknown",) * 3
    assert "does not record the Nmap command line" in context.scan_method
    assert context.generated_at.endswith(" UTC")


def test_build_context_long_duration() -> None:
    start = datetime(2026, 11, 2, tzinfo=timezone.utc)
    result = ScanResult("7.95", None, start, start + timedelta(hours=1, minutes=2, seconds=3))
    assert report.build_context(result).duration == "1h 2m 3s"


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ("nmap -sV 10.0.0.5", "service version detection (-sV) probed"),
        ("nmap -A 10.0.0.5", "service version detection (-sV) probed"),
        ("nmap -sS 10.0.0.5", "does not include service version detection"),
    ],
)
def test_build_context_scan_method(args: str, expected: str) -> None:
    assert expected in report.build_context(_scan(args=args)).scan_method


# --- HTML -----------------------------------------------------------------------


def test_html_report_sections_and_metadata(scanme: ScanResult) -> None:
    page = report.render_html(scanme, generated_at=NOW)
    for section in (
        "1. Executive summary",
        "2. Hosts and open ports",
        "3. Findings",
        "4. Methodology and limitations",
    ):
        assert f">{section}</h2>" in page
    for value in (
        "45.33.32.156",
        "scanme.nmap.org",
        "2026-11-02 18:09:13 UTC",
        "<dd>11s</dd>",
        "<dd>7.993</dd>",
        str(escape(scanme.args)),
        "Authorized testing only.",
        f"Generated by recon-report {__version__} on 2026-11-03 09:30:15 UTC.",
        "Linux distributions often backport security fixes",
        "advisory pages on 2026-11-03",
    ):
        assert value in page
    assert "<title>Reconnaissance report: 45.33.32.156 (scanme.nmap.org)</title>" in page
    assert 'role="note"><strong>Note:</strong>' not in page


def test_html_report_findings_sorted_with_badges(risky: ScanResult) -> None:
    page = report.render_html(risky)
    badges = re.findall(r'<span class="badge">(\w+)</span>', page)
    assert badges == ["Critical"] + ["High"] * 6 + ["Medium"] * 2 + ["Low"]
    assert '<article class="finding sev-critical" id="finding-1">' in page
    assert "Not shown: 1 closed port." in page
    assert "Hosts not up" in page
    assert '<li class="count-card sev-info is-zero">' in page


def test_html_report_shows_notice(scanme: ScanResult) -> None:
    page = report.render_html(scanme, notice="Fictional <lab> data")
    assert '<p class="notice" role="note"><strong>Note:</strong> Fictional &lt;lab&gt; data' in page


@pytest.mark.parametrize("fixture", ["single_host.xml", "risky_host.xml", "minimal.xml"])
def test_html_report_is_self_contained(fixture: str) -> None:
    page = report.render_html(parse_file(FIXTURES / fixture))
    lowered = page.lower()
    for forbidden in ("<link", "<img", "<iframe", " src=", "@import", "url(", "javascript:"):
        assert forbidden not in lowered
    # Exactly one script: the inline "Save as PDF" handler, without attributes.
    assert lowered.count("<script") == 1
    assert page.count("<script>") == 1
    # The only URLs are rule references, shown as links.
    assert set(re.findall(r"https?://[^\s\"<>]+", page)) <= RULE_REFERENCES
    collector = _HTMLCollector(page)
    hrefs = {value for name, value in collector.attrs if name == "href"}
    assert hrefs <= RULE_REFERENCES
    assert not [name for name, _ in collector.attrs if name in ("style", "src", "srcset")]
    # Inline event handlers would need 'unsafe-inline'; the script uses addEventListener.
    assert not [name for name, _ in collector.attrs if name.startswith("on")]


def _sha256_source(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode() + "'"


def test_html_report_csp_allows_only_the_inline_stylesheet_and_script(scanme: ScanResult) -> None:
    page = report.render_html(scanme)
    csp_match = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', page)
    style_match = re.search(r"<style>(.*?)</style>", page, re.DOTALL)
    script_match = re.search(r"<script>(.*?)</script>", page, re.DOTALL)
    assert csp_match and style_match and script_match
    # The policy must be declared before the content it protects.
    assert csp_match.start() < style_match.start() < script_match.start()
    csp = html.unescape(csp_match.group(1))
    assert csp == (
        f"default-src 'none'; script-src {_sha256_source(script_match.group(1))}; "
        f"style-src {_sha256_source(style_match.group(1))}; base-uri 'none'; form-action 'none'"
    )
    assert "unsafe" not in csp
    assert page.count("<style>") == 1


def test_html_report_save_as_pdf_button(scanme: ScanResult) -> None:
    page = report.render_html(scanme)
    script = re.search(r"<script>(.*?)</script>", page, re.DOTALL)
    assert script
    # The script reveals the button and prints on click; without JavaScript the button
    # stays hidden and the <noscript> hint explains how to print.
    button = '<button type="button" class="save-pdf" id="save-pdf" hidden>Save as PDF</button>'
    assert button in page
    assert 'getElementById("save-pdf")' in script.group(1)
    assert 'addEventListener("click", () => window.print())' in script.group(1)
    noscript = re.search(r'<noscript><p class="print-hint">(.*?)</p></noscript>', page)
    assert noscript
    hint = html.unescape(noscript.group(1))
    assert "press Ctrl+P (Cmd+P on Mac)" in hint
    assert "untick “Headers and footers”" in hint


# --- Stylesheet -----------------------------------------------------------------

CSS = resources.files("recon_report").joinpath("templates", "report.css").read_text("utf-8")
SEVERITIES = ("critical", "high", "medium", "low", "info")
# (foreground, background) colour tokens of every text the stylesheet draws.
TEXT_PAIRS = [
    *[(fg, bg) for fg in ("text", "muted") for bg in ("bg", "surface", "subtle")],
    ("accent", "bg"),  # section headings
    ("accent", "surface"),  # eyebrow and links in cards
    ("on-accent", "accent"),  # "Save as PDF" button
    ("text", "note-bg"),
    ("warn-text", "warn-bg"),
    *[("on-sev", f"sev-{sev}") for sev in SEVERITIES],  # badges
    *[(f"sev-{sev}", "surface") for sev in SEVERITIES],  # count card numbers
]
# Colours that only mark something need 3:1 against what they sit on (WCAG 1.4.11).
MARKER_PAIRS = [("note-border", "note-bg"), ("warn-border", "warn-bg")]


def _css_block(css: str, prelude: str) -> str:
    """Return the body of the first ``prelude { ... }`` block, which may contain blocks."""
    start = css.index(prelude + " {") + len(prelude) + 2
    depth = 1
    for index in range(start, len(css)):
        depth += {"{": 1, "}": -1}.get(css[index], 0)
        if depth == 0:
            return css[start:index]
    raise AssertionError(f"Unterminated block: {prelude}")


def _colour_tokens(block: str) -> dict[str, str]:
    return dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})\s*;", block))


def _palette(media: str) -> dict[str, str]:
    """Colour tokens in effect on screen or in print (print overrides some on :root)."""
    tokens = _colour_tokens(_css_block(CSS, ":root"))
    if media == "print":
        tokens |= _colour_tokens(_css_block(_css_block(CSS, "@media print"), ":root"))
    return tokens


def _contrast(first: str, second: str) -> float:
    """WCAG 2.x contrast ratio of two ``#rrggbb`` colours."""

    def luminance(colour: str) -> float:
        channels = [int(colour[i : i + 2], 16) / 255 for i in (1, 3, 5)]
        r, g, b = (c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels)
        return 0.2126 * r + 0.7152 * g + 0.0722 * b

    lighter, darker = sorted((luminance(first), luminance(second)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def test_contrast_helper_matches_known_ratios() -> None:
    assert _contrast("#000000", "#ffffff") == pytest.approx(21)
    assert _contrast("#ffffff", "#777777") == pytest.approx(4.48, abs=0.01)


@pytest.mark.parametrize("media", ["screen", "print"])
@pytest.mark.parametrize(("fg", "bg"), TEXT_PAIRS)
def test_text_colours_meet_wcag_aa(media: str, fg: str, bg: str) -> None:
    palette = _palette(media)
    ratio = _contrast(palette[fg], palette[bg])
    assert ratio >= 4.5, f"{media}: --{fg} on --{bg} is {ratio:.2f}:1"


@pytest.mark.parametrize("media", ["screen", "print"])
@pytest.mark.parametrize(("fg", "bg"), MARKER_PAIRS)
def test_marker_colours_meet_wcag_non_text_contrast(media: str, fg: str, bg: str) -> None:
    palette = _palette(media)
    ratio = _contrast(palette[fg], palette[bg])
    assert ratio >= 3, f"{media}: --{fg} on --{bg} is {ratio:.2f}:1"


@pytest.mark.parametrize("media", ["screen", "print"])
def test_severity_colours_are_distinct_from_each_other_and_the_accent(media: str) -> None:
    palette = _palette(media)
    colours = [palette[f"sev-{sev}"] for sev in SEVERITIES]
    assert len(set(colours)) == len(colours)
    assert palette["accent"] not in colours


def test_screen_theme_is_always_dark_and_print_theme_is_light() -> None:
    assert "prefers-color-scheme" not in CSS
    assert _contrast(_palette("screen")["bg"], "#000000") < 1.5
    assert _palette("print")["bg"] == "#ffffff"
    assert "color-scheme: light" in _css_block(CSS, "@media print")


def test_print_stylesheet_hides_save_as_pdf_controls() -> None:
    hidden: set[str] = set()
    for selectors, body in re.findall(r"([^{}]+)\{([^{}]*)\}", _css_block(CSS, "@media print")):
        if re.search(r"(?:^|;)\s*display:\s*none\s*(?:;|$)", body):
            hidden.update(selector.strip() for selector in selectors.split(","))
    assert {".save-pdf", ".print-hint"} <= hidden


def test_html_report_renders_untrusted_scan_data_as_inert_text(evil: ScanResult) -> None:
    page = report.render_html(evil)
    collector = _HTMLCollector(page)

    assert collector.tags.count("script") == 1  # only the template's own
    assert "img" not in collector.tags
    assert "b" not in collector.tags
    assert not [name for name, _ in collector.attrs if name.startswith("on")]
    assert {value for name, value in collector.attrs if name == "href"} <= RULE_REFERENCES
    # Each payload is shown verbatim as text, in the header, host table and finding.
    assert collector.text.count(EVIL_HOSTNAME) >= 3
    assert EVIL_BANNER in collector.cells
    assert f"telnet: {EVIL_BANNER}" in collector.text
    assert "&lt;script&gt;alert(&#34;host&#34;)&lt;/script&gt;" in page


# --- Markdown -------------------------------------------------------------------


def test_markdown_report_sections_and_metadata(scanme: ScanResult) -> None:
    text = report.render_markdown(scanme, generated_at=NOW)
    for heading in (
        "# Reconnaissance report: 45\\.33\\.32\\.156 \\(scanme\\.nmap\\.org\\)",
        "## 1. Executive summary",
        "## 2. Hosts and open ports",
        "## 3. Findings",
        "## 4. Methodology and limitations",
        "### 1. Medium: Outdated OpenSSH version",
        "### 2. Low: Unencrypted HTTP service",
    ):
        assert f"\n{heading}\n" in f"\n{text}"
    assert "| 0 | 0 | 1 | 1 | 0 |" in text
    assert "| 22\\/tcp | ssh | OpenSSH 6\\.6\\.1p1 Ubuntu 2ubuntu2\\.13" in text
    assert "- <https://www.openssh.org/txt/release-7.4>" in text
    assert "> **Authorized testing only.**" in text
    assert "> **Note:**" not in text
    version = report.escape_markdown(__version__)
    generated = "2026\\-11\\-03 09\\:30\\:15 UTC"
    assert text.endswith(f"*Generated by recon-report {version} on {generated}.*\n")


def test_markdown_report_renders_as_expected_html(risky: ScanResult) -> None:
    rendered = _markdown_to_html(report.render_markdown(risky, notice="Fictional lab data."))
    collector = _HTMLCollector(rendered)
    # Hosts up, "Hosts not up", findings and the three methodology subsections.
    assert collector.tags.count("h3") == 2 + 1 + 10 + 3
    assert collector.tags.count("table") == 3  # severity counts and one per host up
    assert {value for name, value in collector.attrs if name == "href"} <= RULE_REFERENCES
    assert "Not shown: 1 closed port." in collector.text
    assert "Note: Fictional lab data." in collector.text
    assert "Nmap command: nmap -sV -oX risky_host.xml 10.0.0.0/24" in collector.text


def test_markdown_report_renders_untrusted_scan_data_as_inert_text(evil: ScanResult) -> None:
    text = report.render_markdown(evil)

    # Each table row keeps exactly its own column separators.
    rows = [line for line in text.splitlines() if line.startswith("| 23")]
    assert len(rows) == 1
    assert _unescaped(rows[0]).count("|") == 5

    collector = _HTMLCollector(_markdown_to_html(text))
    for tag in ("script", "img", "b", "code", "del", "s", "h4"):
        assert tag not in collector.tags, tag
    assert collector.tags.count("em") == 1  # only the template's own footer
    assert {value for name, value in collector.attrs if name == "href"} <= RULE_REFERENCES
    assert EVIL_BANNER_ONE_LINE in collector.cells
    assert collector.text.count(EVIL_HOSTNAME) >= 3
    assert f"Evidence: telnet: {EVIL_BANNER_ONE_LINE}" in collector.text


def test_markdown_report_escapes_notice_and_keeps_values_on_one_line(scanme: ScanResult) -> None:
    text = report.render_markdown(scanme, notice="line one\n# not a heading | pipe")
    assert "> **Note:** line one \\# not a heading \\| pipe\n" in text


def test_markdown_reference_links_only_for_https_urls() -> None:
    assert report._markdown_link("https://example.org/a_b") == "<https://example.org/a_b>"
    assert report._markdown_link("javascript:alert(1)") == r"javascript\:alert\(1\)"
    assert report._markdown_link("https://x.test/<b>") == r"https\:\/\/x\.test\/\<b\>"


# --- Empty results --------------------------------------------------------------


@pytest.mark.parametrize(
    ("result", "messages"),
    [
        (
            parse_file(FIXTURES / "minimal.xml"),
            ["No hosts reported", "The scan did not report any hosts."],
        ),
        (
            _scan(_host("10.0.0.9", status="down")),
            ["No hosts were up (1 host reported)", "Hosts not up", "10.0.0.9"],
        ),
        (
            _scan(_host("10.0.0.5", _port(22, "ssh", product="OpenSSH", version="9.6"))),
            ["No findings were identified by the current rules", "22/tcp"],
        ),
    ],
    ids=["no-hosts", "hosts-down", "no-findings"],
)
def test_reports_without_findings(result: ScanResult, messages: list[str]) -> None:
    page = report.render_html(result)
    markdown_text = _HTMLCollector(_markdown_to_html(report.render_markdown(result))).text
    for document in (_HTMLCollector(page).text, markdown_text):
        assert "No findings. No open service matched the rules" in document
        for message in messages:
            assert message in document
    assert re.findall(r'<span class="count">(\d+)</span>', page) == ["0"] * 5
    assert 'class="finding ' not in page


# --- Writing files --------------------------------------------------------------


@pytest.mark.parametrize(
    ("fmt", "extensions"),
    [(ReportFormat.HTML, ["html"]), (ReportFormat.MD, ["md"]), (ReportFormat.BOTH, ["html", "md"])],
)
def test_write_reports_names_files_by_host_and_time(
    scanme: ScanResult, tmp_path: Path, fmt: ReportFormat, extensions: list[str]
) -> None:
    out = tmp_path / "nested" / "reports"
    paths = report.write_reports(scanme, assess(scanme), out, fmt, now=NOW)
    assert [path.name for path in paths] == [
        f"report_scanme.nmap.org_20261103T093015Z.{ext}" for ext in extensions
    ]
    for path in paths:
        content = path.read_bytes()
        assert b"\r\n" not in content
        assert b"Reconnaissance report: 45" in content


def test_write_reports_never_overwrites(scanme: ScanResult, tmp_path: Path) -> None:
    (tmp_path / "report_scanme.nmap.org_20261103T093015Z.md").write_text("keep", encoding="utf-8")
    first = report.write_reports(scanme, assess(scanme), tmp_path, ReportFormat.BOTH, now=NOW)
    second = report.write_reports(scanme, assess(scanme), tmp_path, ReportFormat.BOTH, now=NOW)
    # Both formats share the suffix, even though only the .md name was taken.
    assert [path.name for path in first + second] == [
        "report_scanme.nmap.org_20261103T093015Z-1.html",
        "report_scanme.nmap.org_20261103T093015Z-1.md",
        "report_scanme.nmap.org_20261103T093015Z-2.html",
        "report_scanme.nmap.org_20261103T093015Z-2.md",
    ]
    kept = tmp_path / "report_scanme.nmap.org_20261103T093015Z.md"
    assert kept.read_text(encoding="utf-8") == "keep"


@pytest.mark.parametrize(
    ("result", "label"),
    [
        (_scan(), "no-hosts"),
        (_scan(_host("10.0.0.5"), _host("10.0.0.6")), "2-hosts"),
        (_scan(_host("2001:db8::1")), "2001_db8__1"),
        (_scan(_host("10.0.0.5", hostnames=("..\\..\\evil/x:y*?.lab",))), ".._.._evil_x_y__.lab"),
    ],
)
def test_write_reports_filename_is_filesystem_safe(
    result: ScanResult, label: str, tmp_path: Path
) -> None:
    [path] = report.write_reports(result, assess(result), tmp_path, now=NOW)
    assert path.parent == tmp_path
    assert path.name == f"report_{label}_20261103T093015Z.html"


def test_write_reports_unwritable_directory(scanme: ScanResult, tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("not a directory", encoding="utf-8")
    with pytest.raises(report.ReportError, match="Cannot write report"):
        report.write_reports(scanme, assess(scanme), blocker / "reports")


def test_safe_part_caps_length() -> None:
    assert filenames.safe_part("a" * 300) == "a" * filenames.MAX_PART_LENGTH
    assert filenames.safe_part("host name/../x") == "host_name_.._x"


# --- Packaging and examples -----------------------------------------------------


@pytest.mark.parametrize("name", ["report.html.j2", "report.md.j2", "report.css", "report.js"])
def test_templates_are_package_resources(name: str) -> None:
    assert resources.files("recon_report").joinpath("templates", name).is_file()


def test_pages_index_is_self_contained_with_hash_based_csp() -> None:
    # read_text normalizes CRLF to LF, as HTML parsers do before CSP hashing.
    page = (ROOT / "index.html").read_text(encoding="utf-8")
    csp_match = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', page)
    style_match = re.search(r"<style>(.*?)</style>", page, re.DOTALL)
    assert csp_match and style_match
    assert csp_match.start() < style_match.start()
    assert html.unescape(csp_match.group(1)) == (
        f"default-src 'none'; style-src {_sha256_source(style_match.group(1))}; "
        "base-uri 'none'; form-action 'none'"
    )
    lowered = page.lower()
    for forbidden in ("<script", "<link", "<img", "<iframe", " src=", "@import", "url("):
        assert forbidden not in lowered
    collector = _HTMLCollector(page)
    assert not [name for name, _ in collector.attrs if name == "style" or name.startswith("on")]
    hrefs = {value for name, value in collector.attrs if name == "href"}
    assert hrefs == {
        "examples/lab-risky-host.html",
        "examples/scanme.html",
        "https://github.com/senura111/recon-report",
    }
    # GitHub Pages serves the repository root, so relative links must be committed files.
    for href in hrefs - {"https://github.com/senura111/recon-report"}:
        assert (ROOT / href).is_file()


def test_committed_examples_are_up_to_date(monkeypatch: pytest.MonkeyPatch) -> None:
    spec = importlib.util.spec_from_file_location(
        "generate_examples", ROOT / "scripts" / "generate_examples.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # dataclasses looks the module up in sys.modules while the script is executing.
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)

    for name, content in module.render_examples().items():
        path = ROOT / "examples" / name
        assert path.is_file(), f"{name} is missing; run python scripts/generate_examples.py"
        assert path.read_text(encoding="utf-8") == content, (
            f"{name} is out of date; run python scripts/generate_examples.py"
        )
