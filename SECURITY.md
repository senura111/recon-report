# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| < 1.0 | No |

Security fixes are released for the latest 1.0.x version.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability
reporting. **Do not open a public issue, discussion or pull request.**

1. Go to the [Security tab](https://github.com/senura111/recon-report/security)
   of this repository.
2. Click **Report a vulnerability**.
3. Fill in the form and submit it. Only the maintainer can see the report.

GitHub's documentation describes the process in
[Privately reporting a security vulnerability](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).

Please include:

- the recon-report version (`recon-report --version`), Python version and
  operating system;
- what an attacker can do, and what they need to control (for example a crafted
  Nmap XML file, a malicious service banner, or a command-line argument);
- steps or a minimal file to reproduce it.

You can expect an acknowledgement within 7 days. Once the issue is confirmed, a
fix will be prepared and released, and a GitHub security advisory published,
crediting you unless you prefer otherwise.

## Scope

In scope: vulnerabilities in recon-report itself, for example:

- argument injection into the Nmap command, or bypassing single-target validation;
- XML parsing issues such as XXE or entity expansion;
- script or markup injection into the terminal output or the HTML or Markdown
  reports from scan data;
- report files being written outside the chosen output directory.

Out of scope:

- vulnerabilities in the systems you scan; recon-report reports those as findings;
- vulnerabilities in Nmap, Python or third-party dependencies (report them
  upstream, though a note is welcome if recon-report uses them unsafely);
- false positives or missing findings in the risk rules; please open a regular
  issue for those.
