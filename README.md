# recon-report

Defensive reconnaissance and reporting CLI for authorized penetration testing.
`recon-report` runs Nmap service discovery and (soon) turns the results into
HTML and Markdown findings reports.

> **Authorized use only.** Scan only systems you own or have explicit written
> permission to test, such as your own lab VMs or `scanme.nmap.org`.

## Status

Early development. Scanning, parsing and risk rating work; HTML and Markdown
report rendering is still a stub.

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

## License

MIT. See [LICENSE](LICENSE).
