# Reconnaissance report: 3 hosts

> **Note:** Fictional lab data\. This example was generated from a synthetic Nmap scan\: the hosts\, addresses and services do not exist and were made up to demonstrate the risk rules\.

- **Targets:** 10\.0\.0\.20 \(lab\-app\.internal\)\, 10\.0\.0\.3\, 10\.0\.0\.100
- **Scan started:** 2026\-11\-02 12\:00\:00 UTC
- **Scan finished:** 2026\-11\-02 12\:01\:00 UTC
- **Duration:** 1m 0s
- **Nmap version:** 7\.95
- **Nmap command:** nmap \-sV \-oX risky\_host\.xml 10\.0\.0\.0\/24
- **recon-report version:** 0\.1\.0
- **Report generated:** 2026\-11\-02 12\:01\:00 UTC

> **Authorized testing only.** recon-report is intended for authorized security testing. Scan only systems you own or have explicit written permission to test. This report describes the exposure of the scanned systems: handle it as confidential.

## 1. Executive summary

| Critical | High | Medium | Low | Info |
| :---: | :---: | :---: | :---: | :---: |
| 1 | 6 | 2 | 1 | 0 |

2 of 3 hosts were up\, with 10 open ports\. 10 findings were identified \(1 Critical\, 6 High\, 2 Medium and 1 Low\)\. The most severe finding is Docker Engine API exposed without TLS \(Critical\) on 10\.0\.0\.20 \(lab\-app\.internal\)\, port 2375\/tcp\.

## 2. Hosts and open ports

### 10\.0\.0\.20 \(lab\-app\.internal\)

| Port | Service | Version | Detection |
| --- | --- | --- | --- |
| 23\/tcp | telnet | Linux telnetd | Probed |
| 443\/tcp | ssl\/http | nginx 1\.24\.0 | Probed |
| 2375\/tcp | docker | Docker 24\.0\.7 | Probed |
| 3306\/tcp | mysql | MySQL 5\.5\.5\-10\.6\.12\-MariaDB\-0ubuntu0\.22\.04\.1 | Probed |
| 3389\/tcp | ms\-wbt\-server | — | Port number only |
| 5432\/tcp | postgresql | PostgreSQL DB 9\.6\.0 \- 9\.6\.4 | Probed |
| 6379\/tcp | redis | Redis key\-value store 7\.2\.4 | Probed |
| 8080\/tcp | http | Apache httpd 2\.4\.49 \(\(Unix\)\) | Probed |
| 9200\/tcp | http | Elasticsearch REST API 7\.17\.0 \(name\: es01\; cluster\: lab\) | Probed |

Not shown\: 1 closed port\.

### 10\.0\.0\.3

| Port | Service | Version | Detection |
| --- | --- | --- | --- |
| 5900\/tcp | vnc | VNC \(protocol 3\.8\) | Probed |

### Hosts not up

- 10\.0\.0\.100: down

## 3. Findings

Findings are sorted by severity, most severe first.

### 1. Critical: Docker Engine API exposed without TLS

- **Severity:** Critical
- **Confidence:** Confirmed (nmap identified the service by probing it)
- **Host:** 10\.0\.0\.20 (lab\-app\.internal)
- **Port:** 2375/tcp
- **Rule:** RR\-API\-DOCKER
- **Evidence:** docker\: Docker 24\.0\.7

**Description:** The Docker daemon API is reachable over plain TCP\. The API has no authentication of its own\, and anyone who can reach it can start privileged containers\, which is equivalent to root access on the host\.

**Recommendation:** Stop exposing the daemon over TCP\: use the local Unix socket\, or SSH\. If remote TCP access is required\, use TLS with client certificate verification \(\-\-tlsverify\) and restrict the port to trusted hosts\.

**References:**

- <https://docs.docker.com/engine/security/protect-access/>

### 2. High: VNC remote desktop exposed

- **Severity:** High
- **Confidence:** Confirmed (nmap identified the service by probing it)
- **Host:** 10\.0\.0\.3
- **Port:** 5900/tcp
- **Rule:** RR\-REMOTE\-VNC
- **Evidence:** vnc\: VNC \(protocol 3\.8\)

**Description:** VNC often relies on a single shared password\, and classic VNC authentication uses only the first 8 characters of it\. Many deployments send the session unencrypted\, and some allow access with no password at all\.

**Recommendation:** Do not expose VNC directly\. Tunnel it over SSH or a VPN\, require strong authentication\, and prefer a VNC server that supports encryption\. If remote access is required\, allow it only from trusted management networks through a firewall or VPN rather than exposing it broadly\.

### 3. High: Telnet service exposed

- **Severity:** High
- **Confidence:** Confirmed (nmap identified the service by probing it)
- **Host:** 10\.0\.0\.20 (lab\-app\.internal)
- **Port:** 23/tcp
- **Rule:** RR\-CLEARTEXT\-TELNET
- **Evidence:** telnet\: Linux telnetd

**Description:** Telnet sends everything\, including usernames and passwords\, in cleartext\, so anyone on the network path can capture credentials or hijack sessions\.

**Recommendation:** Disable Telnet and use SSH for remote administration\. For devices that only support Telnet\, restrict access to an isolated management network\.

### 4. High: Remote Desktop \(RDP\) exposed

- **Severity:** High
- **Confidence:** Likely (nmap guessed the service from the port number only)
- **Host:** 10\.0\.0\.20 (lab\-app\.internal)
- **Port:** 3389/tcp
- **Rule:** RR\-REMOTE\-RDP
- **Evidence:** ms\-wbt\-server

**Description:** Exposed RDP is a frequent target for password guessing and credential stuffing and a common initial access route for ransomware\. Any unpatched RDP vulnerability is directly reachable\.

**Recommendation:** Do not expose RDP broadly\. Put it behind a VPN or Remote Desktop Gateway\, require Network Level Authentication and multi\-factor authentication\, and enforce account lockout\. If remote access is required\, allow it only from trusted management networks through a firewall or VPN rather than exposing it broadly\.

### 5. High: Redis exposed

- **Severity:** High
- **Confidence:** Confirmed (nmap identified the service by probing it)
- **Host:** 10\.0\.0\.20 (lab\-app\.internal)
- **Port:** 6379/tcp
- **Rule:** RR\-DB\-REDIS
- **Evidence:** redis\: Redis key\-value store 7\.2\.4

**Description:** Redis is designed to be accessed only by trusted clients in trusted environments\. An exposed instance without authentication lets anyone read or modify data and may be abused to write files or execute code on the host\.

**Recommendation:** Bind Redis to localhost or an internal interface\, keep protected mode enabled\, require authentication with ACLs\, and allow only application hosts through the firewall\.

**References:**

- <https://redis.io/docs/latest/operate/oss_and_stack/management/security/>

### 6. High: Apache httpd version with known path traversal vulnerability

- **Severity:** High
- **Confidence:** Potential (based on the banner version\, which may not reflect patch status)
- **Host:** 10\.0\.0\.20 (lab\-app\.internal)
- **Port:** 8080/tcp
- **Rule:** RR\-VER\-APACHE\-PATH\-TRAVERSAL
- **Evidence:** http\: Apache httpd 2\.4\.49 \(\(Unix\)\)

**Description:** The banner reports Apache httpd 2\.4\.49 or 2\.4\.50\. 2\.4\.49 is affected by CVE\-2021\-41773\, and both versions by CVE\-2021\-42013 \(an incomplete fix for the first\)\. Depending on configuration\, these allow reading files outside the document root and\, with CGI enabled\, remote code execution\. The Apache project reports CVE\-2021\-41773 was exploited in the wild\. Linux distributions often backport security fixes without changing the upstream version number\, so the banner version may not reflect the actual patch status\. Verify against the vendor\'s package version before acting\.

**Recommendation:** Upgrade to Apache httpd 2\.4\.51 or later\; a current 2\.4 release is best\.

**References:**

- <https://httpd.apache.org/security/vulnerabilities_24.html>
- <https://nvd.nist.gov/vuln/detail/CVE-2021-41773>
- <https://nvd.nist.gov/vuln/detail/CVE-2021-42013>

### 7. High: Elasticsearch API exposed

- **Severity:** High
- **Confidence:** Confirmed (nmap identified the service by probing it)
- **Host:** 10\.0\.0\.20 (lab\-app\.internal)
- **Port:** 9200/tcp
- **Rule:** RR\-DB\-ELASTICSEARCH
- **Evidence:** http\: Elasticsearch REST API 7\.17\.0 \(name\: es01\; cluster\: lab\)

**Description:** The Elasticsearch REST API is reachable over the network\. Versions before 8\.0 did not enable security by default\, and exposed clusters without authentication have caused large data leaks\.

**Recommendation:** Enable Elasticsearch security \(authentication and TLS\)\, bind to internal interfaces only\, and put the API behind a firewall or authenticated proxy\.

**References:**

- <https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html>

### 8. Medium: MySQL \/ MariaDB database exposed

- **Severity:** Medium
- **Confidence:** Confirmed (nmap identified the service by probing it)
- **Host:** 10\.0\.0\.20 (lab\-app\.internal)
- **Port:** 3306/tcp
- **Rule:** RR\-DB\-MYSQL
- **Evidence:** mysql\: MySQL 5\.5\.5\-10\.6\.12\-MariaDB\-0ubuntu0\.22\.04\.1

**Description:** The database port is reachable over the network\, which allows password guessing against database accounts and direct exposure to any server vulnerability\.

**Recommendation:** Bind the server to localhost or an internal interface \(bind\_address\)\, allow only application hosts through the firewall\, and require strong\, per\-application credentials and TLS\.

**References:**

- <https://dev.mysql.com/doc/refman/8.4/en/security-guidelines.html>

### 9. Medium: PostgreSQL database exposed

- **Severity:** Medium
- **Confidence:** Confirmed (nmap identified the service by probing it)
- **Host:** 10\.0\.0\.20 (lab\-app\.internal)
- **Port:** 5432/tcp
- **Rule:** RR\-DB\-POSTGRESQL
- **Evidence:** postgresql\: PostgreSQL DB 9\.6\.0 \- 9\.6\.4

**Description:** The database port is reachable over the network\, which allows password guessing against database roles and direct exposure to any server vulnerability\. Misconfigured pg\_hba\.conf entries \(e\.g\. trust\) can allow access without a password\.

**Recommendation:** Restrict listen\_addresses to required interfaces\, limit pg\_hba\.conf entries to specific application hosts using scram\-sha\-256 authentication\, require TLS \(hostssl\)\, and filter the port at the firewall\.

**References:**

- <https://www.postgresql.org/docs/current/auth-pg-hba-conf.html>

### 10. Low: Unencrypted HTTP service

- **Severity:** Low
- **Confidence:** Confirmed (nmap identified the service by probing it)
- **Host:** 10\.0\.0\.20 (lab\-app\.internal)
- **Port:** 8080/tcp
- **Rule:** RR\-CLEARTEXT\-HTTP
- **Evidence:** http\: Apache httpd 2\.4\.49 \(\(Unix\)\)

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

*Generated by recon-report 0\.1\.0 on 2026\-11\-02 12\:01\:00 UTC.*
