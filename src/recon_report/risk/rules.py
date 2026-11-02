"""Risk rule definitions. Data only: the evaluation logic lives in :mod:`.engine`.

To add a rule, append a :class:`ServiceRule` or :class:`VersionRule` to the
matching tuple. Rule IDs must be unique. Only cite references that are official
vendor or project pages, and never cite a CVE ID that has not been verified.

Version rule thresholds were checked against official lifecycle and advisory
pages on the date in each rule's ``last_reviewed``. Revisit them when that date
gets old; known upcoming changes are noted next to the affected rule.
"""

from __future__ import annotations

from datetime import date

from recon_report.risk.models import ServiceRule, Severity, VersionRule

_REVIEWED = date(2026, 11, 3)

_FIREWALL = (
    "If remote access is required, allow it only from trusted management networks "
    "through a firewall or VPN rather than exposing it broadly."
)

SERVICE_RULES: tuple[ServiceRule, ...] = (
    # --- Cleartext and legacy protocols --------------------------------------
    ServiceRule(
        rule_id="RR-CLEARTEXT-TELNET",
        title="Telnet service exposed",
        severity=Severity.HIGH,
        services=("telnet",),
        tls=False,
        description=(
            "Telnet sends everything, including usernames and passwords, in cleartext, so "
            "anyone on the network path can capture credentials or hijack sessions."
        ),
        recommendation=(
            "Disable Telnet and use SSH for remote administration. For devices that only "
            "support Telnet, restrict access to an isolated management network."
        ),
    ),
    ServiceRule(
        rule_id="RR-CLEARTEXT-RSERVICES",
        title="Legacy r-service (rlogin/rsh/rexec) exposed",
        severity=Severity.HIGH,
        services=("login", "rlogin", "shell", "rsh", "exec", "rexec"),
        tls=False,
        description=(
            "The Berkeley r-services send data, and in some cases passwords, in cleartext, "
            "and rlogin/rsh can rely on host-based trust (.rhosts, hosts.equiv) that is "
            "easily abused to log in without a password."
        ),
        recommendation="Disable rlogin, rsh and rexec, and use SSH instead.",
    ),
    ServiceRule(
        rule_id="RR-CLEARTEXT-FTP",
        title="FTP service exposed",
        severity=Severity.MEDIUM,
        services=("ftp",),
        tls=False,
        description=(
            "Plain FTP sends credentials and file contents in cleartext. A port scan cannot "
            "tell whether the server enforces explicit TLS (FTPS), so it may also accept "
            "unencrypted logins or anonymous access."
        ),
        recommendation=(
            "Replace FTP with SFTP or FTPS. If FTP must stay, require TLS for all sessions, "
            "disable anonymous access, and restrict who can reach the service."
        ),
    ),
    ServiceRule(
        rule_id="RR-CLEARTEXT-HTTP",
        title="Unencrypted HTTP service",
        severity=Severity.LOW,
        services=("http", "http-alt"),
        tls=False,
        fallback=True,
        description=(
            "The service is served over plain HTTP, so traffic, including any credentials or "
            "session cookies, can be read or modified in transit. This is expected if the "
            "port only redirects to HTTPS."
        ),
        recommendation=(
            "Serve the site over HTTPS, redirect HTTP to HTTPS, and enable HTTP Strict "
            "Transport Security (HSTS) once HTTPS is in place."
        ),
    ),
    # --- Remote administration -----------------------------------------------
    ServiceRule(
        rule_id="RR-REMOTE-RDP",
        title="Remote Desktop (RDP) exposed",
        severity=Severity.HIGH,
        services=("ms-wbt-server",),
        description=(
            "Exposed RDP is a frequent target for password guessing and credential stuffing "
            "and a common initial access route for ransomware. Any unpatched RDP "
            "vulnerability is directly reachable."
        ),
        recommendation=(
            "Do not expose RDP broadly. Put it behind a VPN or Remote Desktop Gateway, require "
            "Network Level Authentication and multi-factor authentication, and enforce "
            "account lockout. " + _FIREWALL
        ),
    ),
    ServiceRule(
        rule_id="RR-REMOTE-VNC",
        title="VNC remote desktop exposed",
        severity=Severity.HIGH,
        services=("vnc",),
        description=(
            "VNC often relies on a single shared password, and classic VNC authentication "
            "uses only the first 8 characters of it. Many deployments send the session "
            "unencrypted, and some allow access with no password at all."
        ),
        recommendation=(
            "Do not expose VNC directly. Tunnel it over SSH or a VPN, require strong "
            "authentication, and prefer a VNC server that supports encryption. " + _FIREWALL
        ),
    ),
    ServiceRule(
        rule_id="RR-REMOTE-SMB",
        title="SMB / NetBIOS file sharing exposed",
        severity=Severity.HIGH,
        services=("microsoft-ds", "netbios-ssn"),
        description=(
            "SMB exposes file shares and Windows remote management functions. It is a common "
            "target for password guessing and has a history of wormable vulnerabilities, so "
            "it should never be reachable from untrusted networks."
        ),
        recommendation=(
            "Block SMB (445/tcp) and NetBIOS (139/tcp) at the network perimeter, disable "
            "SMBv1, require SMB signing, and limit access to the hosts that need it."
        ),
    ),
    # --- Databases and management APIs ---------------------------------------
    ServiceRule(
        rule_id="RR-DB-MYSQL",
        title="MySQL / MariaDB database exposed",
        severity=Severity.MEDIUM,
        services=("mysql",),
        description=(
            "The database port is reachable over the network, which allows password "
            "guessing against database accounts and direct exposure to any server "
            "vulnerability."
        ),
        recommendation=(
            "Bind the server to localhost or an internal interface (bind_address), allow "
            "only application hosts through the firewall, and require strong, per-application "
            "credentials and TLS."
        ),
        references=("https://dev.mysql.com/doc/refman/8.4/en/security-guidelines.html",),
    ),
    ServiceRule(
        rule_id="RR-DB-POSTGRESQL",
        title="PostgreSQL database exposed",
        severity=Severity.MEDIUM,
        services=("postgresql",),
        description=(
            "The database port is reachable over the network, which allows password "
            "guessing against database roles and direct exposure to any server "
            "vulnerability. Misconfigured pg_hba.conf entries (e.g. trust) can allow access "
            "without a password."
        ),
        recommendation=(
            "Restrict listen_addresses to required interfaces, limit pg_hba.conf entries to "
            "specific application hosts using scram-sha-256 authentication, require TLS "
            "(hostssl), and filter the port at the firewall."
        ),
        references=("https://www.postgresql.org/docs/current/auth-pg-hba-conf.html",),
    ),
    ServiceRule(
        rule_id="RR-DB-MSSQL",
        title="Microsoft SQL Server exposed",
        severity=Severity.MEDIUM,
        services=("ms-sql-s",),
        description=(
            "The SQL Server port is reachable over the network, which allows password "
            "guessing (especially against the sa account) and direct exposure to any "
            "server vulnerability."
        ),
        recommendation=(
            "Allow only application hosts through the firewall, prefer Windows "
            "authentication, disable or rename the sa login if SQL authentication is not "
            "needed, and require encrypted connections."
        ),
    ),
    ServiceRule(
        rule_id="RR-DB-MONGODB",
        title="MongoDB database exposed",
        severity=Severity.HIGH,
        services=("mongodb",),
        description=(
            "MongoDB deployments without access control enabled accept unauthenticated "
            "connections, and exposed instances are routinely found and wiped or held for "
            "ransom. A scan cannot tell whether authentication is enforced."
        ),
        recommendation=(
            "Enable access control and authentication, bind MongoDB only to required "
            "interfaces (net.bindIp), enable TLS, and allow only application hosts through "
            "the firewall."
        ),
        references=("https://www.mongodb.com/docs/manual/administration/security-checklist/",),
    ),
    ServiceRule(
        rule_id="RR-DB-REDIS",
        title="Redis exposed",
        severity=Severity.HIGH,
        services=("redis",),
        description=(
            "Redis is designed to be accessed only by trusted clients in trusted "
            "environments. An exposed instance without authentication lets anyone read or "
            "modify data and may be abused to write files or execute code on the host."
        ),
        recommendation=(
            "Bind Redis to localhost or an internal interface, keep protected mode enabled, "
            "require authentication with ACLs, and allow only application hosts through the "
            "firewall."
        ),
        references=("https://redis.io/docs/latest/operate/oss_and_stack/management/security/",),
    ),
    ServiceRule(
        rule_id="RR-DB-ELASTICSEARCH",
        title="Elasticsearch API exposed",
        severity=Severity.HIGH,
        services=("elasticsearch",),
        products=("Elasticsearch",),
        description=(
            "The Elasticsearch REST API is reachable over the network. Versions before 8.0 "
            "did not enable security by default, and exposed clusters without "
            "authentication have caused large data leaks."
        ),
        recommendation=(
            "Enable Elasticsearch security (authentication and TLS), bind to internal "
            "interfaces only, and put the API behind a firewall or authenticated proxy."
        ),
        references=(
            "https://www.elastic.co/guide/en/elasticsearch/reference/current/"
            "security-minimal-setup.html",
        ),
    ),
    ServiceRule(
        rule_id="RR-API-DOCKER",
        title="Docker Engine API exposed without TLS",
        severity=Severity.CRITICAL,
        services=("docker",),
        tls=False,
        description=(
            "The Docker daemon API is reachable over plain TCP. The API has no "
            "authentication of its own, and anyone who can reach it can start privileged "
            "containers, which is equivalent to root access on the host."
        ),
        recommendation=(
            "Stop exposing the daemon over TCP: use the local Unix socket, or SSH. If "
            "remote TCP access is required, use TLS with client certificate verification "
            "(--tlsverify) and restrict the port to trusted hosts."
        ),
        references=("https://docs.docker.com/engine/security/protect-access/",),
    ),
    ServiceRule(
        rule_id="RR-API-DOCKER-TLS",
        title="Docker Engine API exposed over TLS",
        severity=Severity.MEDIUM,
        services=("docker", "docker-s"),
        tls=True,
        description=(
            "The Docker daemon API is reachable over TLS. This is safe only if the daemon "
            "verifies client certificates (--tlsverify), which a port scan cannot confirm. "
            "Anyone holding a valid client key has root-equivalent access to the host."
        ),
        recommendation=(
            "Confirm the daemon runs with --tlsverify and a dedicated CA, protect client "
            "keys like root credentials, and restrict the port to trusted hosts."
        ),
        references=("https://docs.docker.com/engine/security/protect-access/",),
    ),
)

VERSION_RULES: tuple[VersionRule, ...] = (
    VersionRule(
        rule_id="RR-VER-OPENSSH-OUTDATED",
        title="Outdated OpenSSH version",
        severity=Severity.MEDIUM,
        products=("OpenSSH",),
        below="7.4",
        last_reviewed=_REVIEWED,
        description=(
            "The banner reports an OpenSSH release older than 7.4 (December 2016), the "
            "release that removed server support for the obsolete SSH-1 protocol. Such old "
            "releases lack years of upstream security fixes. OpenSSH does not publish an "
            "end-of-life schedule, so only clearly outdated releases are flagged."
        ),
        recommendation=(
            "Upgrade OpenSSH through a supported operating system release or to a current "
            "upstream version, and disable legacy key exchange algorithms and ciphers."
        ),
        references=(
            "https://www.openssh.org/txt/release-7.4",
            "https://www.openssh.org/security.html",
        ),
    ),
    VersionRule(
        rule_id="RR-VER-APACHE-EOL",
        title="End-of-life Apache httpd version",
        severity=Severity.MEDIUM,
        products=("Apache httpd",),
        below="2.4",
        last_reviewed=_REVIEWED,
        description=(
            "The banner reports Apache httpd 2.2 or older. The 2.2 series is end-of-life: "
            "2.2.34 (July 2017) was its final release, and the Apache project stopped "
            "publishing 2.2 security advisories in January 2018."
        ),
        recommendation="Upgrade to a current Apache httpd 2.4 release.",
        references=("https://archive.apache.org/dist/httpd/Announcement2.2.html",),
    ),
    VersionRule(
        rule_id="RR-VER-APACHE-PATH-TRAVERSAL",
        title="Apache httpd version with known path traversal vulnerability",
        severity=Severity.HIGH,
        products=("Apache httpd",),
        versions=("2.4.49", "2.4.50"),
        last_reviewed=_REVIEWED,
        description=(
            "The banner reports Apache httpd 2.4.49 or 2.4.50. 2.4.49 is affected by "
            "CVE-2021-41773, and both versions by CVE-2021-42013 (an incomplete fix for the "
            "first). Depending on configuration, these allow reading files outside the "
            "document root and, with CGI enabled, remote code execution. The Apache project "
            "reports CVE-2021-41773 was exploited in the wild."
        ),
        recommendation="Upgrade to Apache httpd 2.4.51 or later; a current 2.4 release is best.",
        references=(
            "https://httpd.apache.org/security/vulnerabilities_24.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
        ),
    ),
    VersionRule(
        rule_id="RR-VER-VSFTPD-BACKDOOR",
        title="vsftpd version associated with a backdoored release",
        severity=Severity.HIGH,
        products=("vsftpd",),
        versions=("2.3.4",),
        last_reviewed=_REVIEWED,
        description=(
            "The banner reports vsftpd 2.3.4. Copies of this release downloaded between "
            "30 June and 3 July 2011 contained a backdoor (CVE-2011-2523) that opens a shell "
            "on port 6200/tcp. The banner cannot show whether this copy is the backdoored "
            "one, but 2.3.4 is in any case a 2011 release."
        ),
        recommendation=(
            "Replace vsftpd with a current version from a trusted package source, and check "
            "the host for an unexpected listener on port 6200/tcp."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2011-2523",),
    ),
    VersionRule(
        rule_id="RR-VER-IIS-EOL",
        title="Microsoft IIS on an end-of-life Windows Server",
        severity=Severity.MEDIUM,
        products=("Microsoft IIS httpd",),
        below="10.0",
        last_reviewed=_REVIEWED,
        description=(
            "The banner reports IIS older than 10.0. IIS versions are tied to Windows Server "
            "releases, and every release that ships IIS before 10.0 is out of extended "
            "support: IIS 7.0/7.5 (Windows Server 2008/2008 R2) since January 2020 and "
            "IIS 8.0/8.5 (Windows Server 2012/2012 R2) since October 2023."
        ),
        recommendation=(
            "Migrate the site to a supported Windows Server release. Until then, isolate the "
            "server and limit who can reach it."
        ),
        references=(
            "https://learn.microsoft.com/en-us/lifecycle/products/internet-information-services-iis",
        ),
    ),
    VersionRule(
        rule_id="RR-VER-MYSQL-EOL",
        title="End-of-life MySQL version",
        severity=Severity.MEDIUM,
        products=("MySQL",),
        below="8.4",
        # MariaDB servers report a "5.5.5-<mariadb version>" banner for compatibility.
        exclude=("MariaDB",),
        last_reviewed=_REVIEWED,
        description=(
            "The banner reports MySQL older than 8.4. MySQL 8.0 moved to Oracle Sustaining "
            "Support in April 2026 and 5.7 in October 2023, and the 8.1-8.3 Innovation "
            "releases were supported only until the next Innovation release. 8.4 is the "
            "oldest supported LTS series."
        ),
        recommendation="Upgrade to a supported MySQL LTS series (8.4 or later).",
        references=(
            "https://www.mysql.com/support/eol-notice.html",
            "https://dev.mysql.com/doc/refman/8.4/en/mysql-releases.html",
        ),
    ),
    # PostgreSQL 14's final release is scheduled for 2026-11-12: raise `below` to "15"
    # after that date.
    VersionRule(
        rule_id="RR-VER-POSTGRESQL-EOL",
        title="End-of-life PostgreSQL version",
        severity=Severity.MEDIUM,
        products=("PostgreSQL DB",),
        below="14",
        last_reviewed=_REVIEWED,
        description=(
            "The banner reports PostgreSQL 13 or older. PostgreSQL supports each major "
            "version for five years, and 13 and earlier no longer receive fixes (13's final "
            "release was in November 2025)."
        ),
        recommendation="Upgrade to a supported PostgreSQL major version.",
        references=("https://www.postgresql.org/support/versioning/",),
    ),
)
