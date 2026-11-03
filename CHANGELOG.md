# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-03

First public release.

### Added

- `scan` command: runs an Nmap service version scan (`-sV`) against a single IP
  address or hostname, with optional ports and timeout, and saves the XML with a
  timestamped name. `--report` writes a report straight after the scan.
- `parse` command: prints the hosts and open ports in an Nmap XML file.
- `findings` command: rates each open service and prints a severity summary and
  a findings table, most severe first. `--fail-on SEVERITY` exits with code 3
  when a finding is at or above the threshold, for use in CI.
- `report` command: writes an HTML and/or Markdown findings report with an
  executive summary, open ports per host, one card per finding and a methodology
  and limitations section. Existing files are never overwritten.
- Risk engine with 15 service exposure rules (cleartext and legacy protocols,
  remote administration, databases and management APIs) and 7 version rules
  (outdated, end-of-life or known-vulnerable releases of OpenSSH, Apache httpd,
  vsftpd, IIS, MySQL and PostgreSQL). Findings carry a severity and a confidence
  level (`confirmed`, `likely` or `potential`).
- Self-contained HTML reports: dark theme on screen, light layout when printed,
  and a "Save as PDF" button.
- Example reports for scanme.nmap.org and a fictional lab scan, published with
  GitHub Pages, plus scripts to regenerate the examples and README screenshots.

### Security

- Targets are validated as a single IP address or hostname; ranges, CIDR blocks,
  lists and option-like values are rejected. Nmap runs with an argument list and
  a timeout, never through a shell.
- Nmap XML is parsed with defusedxml, rejecting entity expansion and XXE.
- Scan data is printed as plain text in the terminal, so it cannot inject rich
  markup.
- HTML reports autoescape all values and use a Content-Security-Policy that allows
  only the inline stylesheet and script by SHA-256 hash.
- Markdown reports escape all ASCII punctuation in scan values and keep each value
  on one line.

[1.0.0]: https://github.com/senura111/recon-report/releases/tag/v1.0.0
