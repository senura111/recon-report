# recon-report

Defensive reconnaissance and reporting CLI for authorized penetration testing.
`recon-report` runs Nmap service discovery and (soon) turns the results into
HTML and Markdown findings reports.

> **Authorized use only.** Scan only systems you own or have explicit written
> permission to test, such as your own lab VMs or `scanme.nmap.org`.

## Status

Early development. Scanning works; parsing, risk rating and report rendering
are still stubs.

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
```

## License

MIT. See [LICENSE](LICENSE).
