# recon-report

[![CI](https://github.com/senura111/recon-report/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/senura111/recon-report/actions/workflows/ci.yml)
![Python 3.10 | 3.11 | 3.12 | 3.13 | 3.14](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)

Defensive reconnaissance and reporting CLI for authorized penetration testing.
`recon-report` runs Nmap service discovery, rates the services it finds, and
turns the results into HTML and Markdown findings reports.

> **Authorized use only.** Scan only systems you own or have explicit written
> permission to test, such as your own lab VMs or `scanme.nmap.org`.

## Status

Early development. Scanning, parsing, risk rating and HTML/Markdown reports
work.

## Requirements

- Python 3.10+
- [Nmap](https://nmap.org/download.html) on your `PATH`

## Install (development)

```bash
py -m venv .venv
.venv\Scripts\activate
python -m pip install -e ".[dev]"
```

## Usage

```bash
recon-report scan scanme.nmap.org --ports 22,80 --output scans
recon-report parse scans/scan_scanme.nmap.org_<timestamp>.xml
recon-report findings scans/scan_scanme.nmap.org_<timestamp>.xml
recon-report report scans/scan_scanme.nmap.org_<timestamp>.xml --format both
```

`findings` rates each open service and prints a severity summary and a table
of findings, most severe first. Findings come from two kinds of rule, defined
in `src/recon_report/risk/rules.py`:

- **Service exposure**: cleartext or legacy protocols (Telnet, r-services, FTP,
  plain HTTP), remote administration (RDP, VNC, SMB), and databases or
  management APIs (MySQL, PostgreSQL, MSSQL, MongoDB, Redis, Elasticsearch,
  Docker Engine API).
- **Version**: clearly outdated, end-of-life or known-vulnerable releases.
  These always have `potential` confidence, because distributions often
  backport fixes without changing the version in the banner.

Use `--fail-on` in CI to fail the build when any finding is at or above a
severity:

```bash
recon-report findings scan.xml --fail-on high
```

| Exit code | Meaning |
|---|---|
| 0 | Success, and no finding at or above `--fail-on` |
| 1 | The XML file could not be read or parsed |
| 2 | Invalid arguments, e.g. an unknown severity |
| 3 | At least one finding at or above `--fail-on` |

## Reports

`report` writes a findings report for an Nmap XML file; `scan --report` does
the same straight after a scan. The format is `html` (default), `md` or `both`:

```bash
recon-report report scan.xml --format both --output reports
recon-report scan scanme.nmap.org --ports 22,80 --report both --report-dir reports
```

Reports are written to `reports/` by default, with timestamped names such as
`report_scanme.nmap.org_20261102T180924Z.html`. Existing files are never
overwritten, and the path of each report is printed.

Each report has a header (targets, scan time and duration, Nmap version and
command, tool version), an executive summary with severity counts, a table of
open ports per host, one card per finding (severity, confidence, evidence,
description, recommendation and references), and a methodology and
limitations section.

### Examples

These were generated from the test fixtures and are committed so you can view
them without installing anything:

- scanme.nmap.org, a host the Nmap Project provides for authorized test
  scanning: [Markdown](examples/scanme.md), [HTML](examples/scanme.html)
- Fictional lab data from a synthetic scan:
  [Markdown](examples/lab-risky-host.md), [HTML](examples/lab-risky-host.html)

GitHub shows the HTML files as source; download one and open it in a browser
to see the formatted report. To regenerate the examples after changing the
templates or rules, run `python scripts/generate_examples.py`.

### Report security

Scan data (hostnames, banners, versions) comes from the network and is treated
as untrusted:

- **HTML** reports escape every value (Jinja2 autoescaping) and are a single
  self-contained file: inline CSS, no external fonts, images or requests, and
  a single small inline script for the "Save as PDF" button (no inline event
  handlers). A Content-Security-Policy that allows only the inline stylesheet
  and that script, by hash, is included as defense in depth; it never allows
  `'unsafe-inline'`. Reports use a dark theme on screen and print in a clean
  light layout, so "Save as PDF" (or Ctrl+P) gives an ink-friendly PDF.
- **Markdown** reports backslash-escape all ASCII punctuation in values and
  put each value on one line, so scan data cannot break tables or inject
  formatting, links or HTML.

## License

MIT. See [LICENSE](LICENSE).
