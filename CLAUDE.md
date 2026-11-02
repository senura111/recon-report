\# recon-report



Defensive reconnaissance and reporting CLI for authorized penetration testing.

Automates Nmap service discovery and produces professional HTML and Markdown

findings reports. Targets are limited to systems the operator owns or is

explicitly authorized to test (e.g. lab VMs, scanme.nmap.org).

Out of scope: exploitation, payloads, evasion, or stealth features.



\## Tech stack

\- Python 3.10+, src layout, pyproject.toml

\- CLI: Typer

\- Templating: Jinja2

\- Testing: pytest. Linting and formatting: ruff

\- Type hints throughout; docstrings on public functions

\- Windows: use the `py` launcher (e.g. `py -m venv .venv`); `python` is only available inside the activated venv



\## Architecture

\- scanner: runs nmap and stores XML output

\- parser: converts nmap XML into dataclasses

\- risk/ (package): severity rules for services and versions

  \- risk/models.py: Severity (orderable), Confidence, Finding, ServiceRule, VersionRule

  \- risk/rules.py: rule definitions only (SERVICE_RULES, VERSION_RULES); add rules here. Every VersionRule has a last_reviewed date; recheck thresholds against official lifecycle pages

  \- risk/engine.py: assess() evaluates a ScanResult and returns sorted findings and severity counts; version parsing and comparison

\- report: renders HTML and Markdown reports

\- cli: command-line entry point



\## Conventions

\- Never use shell=True; call subprocess with an argument list and a timeout

\- Validate targets before scanning

\- Parser and risk logic must be testable without running nmap (use XML fixtures)

\- Commit messages follow Conventional Commits (feat:, fix:, docs:, test:, ci:, chore:)



\## Workflow

\- Propose a plan before large changes and wait for approval

\- Run pytest and ruff after changes

