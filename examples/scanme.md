# Reconnaissance report: 45\.33\.32\.156 \(scanme\.nmap\.org\)

> **Note:** Example report from a real scan of scanme\.nmap\.org\, a host the Nmap Project provides for authorized test scanning\.

- **Targets:** 45\.33\.32\.156 \(scanme\.nmap\.org\)
- **Scan started:** 2026\-11\-02 18\:09\:13 UTC
- **Scan finished:** 2026\-11\-02 18\:09\:24 UTC
- **Duration:** 11s
- **Nmap version:** 7\.993
- **Nmap command:** \"C\:\\\\Program Files \(x86\)\\\\Nmap\\\\nmap\.EXE\" \-sV \-oX scans\\\\scan\_scanme\.nmap\.org\_20261102T180912Z\.xml \-p 22\,80 scanme\.nmap\.org
- **recon-report version:** 0\.1\.0
- **Report generated:** 2026\-11\-02 18\:09\:24 UTC

> **Authorized testing only.** recon-report is intended for authorized security testing. Scan only systems you own or have explicit written permission to test. This report describes the exposure of the scanned systems: handle it as confidential.

## 1. Executive summary

| Critical | High | Medium | Low | Info |
| :---: | :---: | :---: | :---: | :---: |
| 0 | 0 | 1 | 1 | 0 |

1 of 1 host was up\, with 2 open ports\. 2 findings were identified \(1 Medium and 1 Low\)\. The most severe finding is Outdated OpenSSH version \(Medium\) on 45\.33\.32\.156 \(scanme\.nmap\.org\)\, port 22\/tcp\.

## 2. Hosts and open ports

### 45\.33\.32\.156 \(scanme\.nmap\.org\)

| Port | Service | Version | Detection |
| --- | --- | --- | --- |
| 22\/tcp | ssh | OpenSSH 6\.6\.1p1 Ubuntu 2ubuntu2\.13 \(Ubuntu Linux\; protocol 2\.0\) | Probed |
| 80\/tcp | http | Apache httpd 2\.4\.7 \(\(Ubuntu\)\) | Probed |

## 3. Findings

Findings are sorted by severity, most severe first.

### 1. Medium: Outdated OpenSSH version

- **Severity:** Medium
- **Confidence:** Potential (based on the banner version\, which may not reflect patch status)
- **Host:** 45\.33\.32\.156 (scanme\.nmap\.org)
- **Port:** 22/tcp
- **Rule:** RR\-VER\-OPENSSH\-OUTDATED
- **Evidence:** ssh\: OpenSSH 6\.6\.1p1 Ubuntu 2ubuntu2\.13 \(Ubuntu Linux\; protocol 2\.0\)

**Description:** The banner reports an OpenSSH release older than 7\.4 \(December 2016\)\, the release that removed server support for the obsolete SSH\-1 protocol\. Such old releases lack years of upstream security fixes\. OpenSSH does not publish an end\-of\-life schedule\, so only clearly outdated releases are flagged\. Linux distributions often backport security fixes without changing the upstream version number\, so the banner version may not reflect the actual patch status\. Verify against the vendor\'s package version before acting\.

**Recommendation:** Upgrade OpenSSH through a supported operating system release or to a current upstream version\, and disable legacy key exchange algorithms and ciphers\.

**References:**

- <https://www.openssh.org/txt/release-7.4>
- <https://www.openssh.org/security.html>

### 2. Low: Unencrypted HTTP service

- **Severity:** Low
- **Confidence:** Confirmed (nmap identified the service by probing it)
- **Host:** 45\.33\.32\.156 (scanme\.nmap\.org)
- **Port:** 80/tcp
- **Rule:** RR\-CLEARTEXT\-HTTP
- **Evidence:** http\: Apache httpd 2\.4\.7 \(\(Ubuntu\)\)

**Description:** The service is served over plain HTTP\, so traffic\, including any credentials or session cookies\, can be read or modified in transit\. This is expected if the port only redirects to HTTPS\.

**Recommendation:** Serve the site over HTTPS\, redirect HTTP to HTTPS\, and enable HTTP Strict Transport Security \(HSTS\) once HTTPS is in place\.

## 4. Methodology and limitations

### How the scan was run

Hosts and services were discovered with Nmap using the command shown in the report header. Nmap service version detection \(\-sV\) probed each open port and identified the product and version from the service\'s responses\.

Each open port on each host that was up was then assessed against recon-report's built-in rules: 15 service exposure rules (cleartext protocols, remote administration, databases and management APIs) and 7 version rules (outdated, end-of-life or known-vulnerable releases). No exploitation, authentication attempts or vulnerability probing were performed.

### Confidence levels

- **Confirmed:** nmap identified the service by probing it.
- **Likely:** nmap guessed the service from the port number only.
- **Potential:** based on the banner version\, which may not reflect patch status.

### Limitations

- Version findings are based only on the version reported in the service banner. Linux distributions often backport security fixes without changing the upstream version number\, so the banner version may not reflect the actual patch status\. Verify against the vendor\'s package version before acting\.
- Version rule thresholds were last reviewed against official vendor lifecycle and advisory pages on 2026\-11\-03. Releases and end-of-life dates after that are not reflected.
- The scan shows only what was reachable from the scanning host at the time of the scan. Filtered ports, ports and protocols that were not scanned, and changes made after the scan are not covered.
- Findings indicate exposure and likely risk, not confirmed vulnerabilities. The absence of findings does not mean a host is secure.

---

*Generated by recon-report 0\.1\.0 on 2026\-11\-02 18\:09\:24 UTC.*
