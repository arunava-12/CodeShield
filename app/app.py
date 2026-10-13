from flask import Flask, jsonify, render_template, request
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix

from datetime import datetime, timezone
from urllib.parse import quote, urlparse
import http.client
import ipaddress
import socket
import ssl
import threading
import hmac

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024  # Limit scan API request bodies to 1 MiB.

# In-process rate limiting is a useful single-instance abuse guard. For multi-worker
# deployments, put a shared rate limiter at the proxy/API gateway.
_RATE_LIMIT_LOCK = threading.Lock()
_RATE_LIMIT_BUCKETS = defaultdict(deque)


# ============================================================
# Application Configuration
# ============================================================

START_TIME = time.time()

VERSION = os.getenv(
    "APP_VERSION",
    "1.0.0"
)

ENVIRONMENT = os.getenv(
    "ENVIRONMENT",
    "development"
)

# In production the app is reachable only through the single Caddy reverse proxy.
# Trust one forwarded client IP/protocol hop there; local development trusts no proxy.
if ENVIRONMENT.strip().lower() == "production":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

GITLEAKS_PATH = os.getenv(
    "GITLEAKS_PATH",
    "gitleaks"
)

TRIVY_PATH = os.getenv(
    "TRIVY_PATH",
    "trivy"
)

GIT_PATH = os.getenv(
    "GIT_PATH",
    "git"
)


# ============================================================
# GitHub Repository Validation
# ============================================================

def validate_github_url(repository_url):
    """
    Validate a public GitHub HTTPS repository URL.

    Accepted examples:
        https://github.com/arunava-12/zenspace-main
        https://github.com/arunava-12/zenspace-main.git

    Returns:
        Normalized Git clone URL
        or None if invalid.
    """

    if not repository_url:
        return None

    try:
        parsed = urlparse(
            repository_url.strip()
        )
    except Exception:
        return None

    # Only HTTPS
    if parsed.scheme.lower() != "https":
        return None

    # Only github.com
    if parsed.hostname is None or parsed.hostname.lower() != "github.com" or parsed.username or parsed.password or parsed.port is not None:
        return None

    path = parsed.path.strip("/")

    # Remove .git if supplied
    if path.endswith(".git"):
        path = path[:-4]

    parts = path.split("/")

    # Must be owner/repository
    if len(parts) != 2:
        return None

    owner = parts[0]
    repository = parts[1]

    github_name_pattern = r"^[A-Za-z0-9_.-]+$"

    if not re.match(
        github_name_pattern,
        owner
    ):
        return None

    if not re.match(
        github_name_pattern,
        repository
    ):
        return None

    return (
        f"https://github.com/"
        f"{owner}/{repository}.git"
    )


# ============================================================
# Repository Cloning
# ============================================================

def clone_repository(repository_url):
    """
    Clone a public GitHub repository into a temporary directory.

    The temporary directory is NOT deleted here.

    The caller is responsible for cleanup after all security
    scanners have finished.
    """

    clone_url = validate_github_url(
        repository_url
    )

    if clone_url is None:
        raise ValueError(
            "Only valid public GitHub HTTPS repository "
            "URLs are supported."
        )

    temporary_directory = tempfile.mkdtemp(
        prefix="codeshield-"
    )

    repository_directory = os.path.join(
        temporary_directory,
        "repository"
    )

    command = [
        GIT_PATH,
        "clone",
        clone_url,
        repository_directory
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
            check=False
        )

    except FileNotFoundError:
        shutil.rmtree(
            temporary_directory,
            ignore_errors=True
        )

        raise RuntimeError(
            "Git was not found. "
            "Make sure Git is installed and available "
            "through PATH or GIT_PATH."
        )

    except subprocess.TimeoutExpired:
        shutil.rmtree(
            temporary_directory,
            ignore_errors=True
        )

        raise RuntimeError(
            "Repository clone timed out after 5 minutes."
        )

    if result.returncode != 0:

        shutil.rmtree(
            temporary_directory,
            ignore_errors=True
        )
        raise RuntimeError(
            "Git clone failed. Verify that the public repository exists and is accessible."
        )

    file_count = 0

    for root, directories, files in os.walk(
        repository_directory
    ):
        file_count += len(files)

    return {
        "repository": repository_url,
        "clone_status": "success",
        "files_discovered": file_count,
        "repository_directory": repository_directory,
        "temporary_directory": temporary_directory
    }


# ============================================================
# Gitleaks Scanner
# ============================================================

def run_gitleaks_scan(repository_directory):
    """
    Run Gitleaks against a cloned repository.

    Returns normalized CodeShield findings.
    """

    # Store report outside the repository so that the
    # generated report itself is never scanned as source.
    report_directory = tempfile.mkdtemp(
        prefix="codeshield-gitleaks-"
    )

    report_path = os.path.join(
        report_directory,
        "gitleaks-report.json"
    )

    command = [
        GITLEAKS_PATH,
        "detect",
        "--source",
        repository_directory,
        "--no-banner",
        "--redact",
        "--report-format",
        "json",
        "--report-path",
        report_path
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False
        )

    except FileNotFoundError:

        shutil.rmtree(
            report_directory,
            ignore_errors=True
        )

        raise RuntimeError(
            "Gitleaks was not found.\n\n"
            "Make sure GITLEAKS_PATH is configured "
            "correctly.\n\n"
            f"Current value: {GITLEAKS_PATH}"
        )

    except subprocess.TimeoutExpired:

        shutil.rmtree(
            report_directory,
            ignore_errors=True
        )

        raise RuntimeError(
            "Gitleaks scan timed out."
        )

    try:

        # Gitleaks:
        #
        # 0 = no leaks
        # 1 = leaks detected
        # other = scanner error

        if result.returncode not in (
            0,
            1
        ):

            raise RuntimeError("Gitleaks scan failed. Check server logs for details.")

        # Gitleaks normally creates the JSON report
        # even when there are no findings.

        if not os.path.isfile(report_path):
            raise RuntimeError("Gitleaks did not generate a JSON report.")
        else:

            try:

                with open(
                    report_path,
                    "r",
                    encoding="utf-8"
                ) as report_file:

                    gitleaks_results = (
                        json.load(report_file)
                    )

            except (OSError, json.JSONDecodeError, UnicodeDecodeError):

                raise RuntimeError(
                    "Gitleaks returned an invalid "
                    "JSON report."
                )

        if not isinstance(gitleaks_results, list) or any(not isinstance(item, dict) for item in gitleaks_results):
            raise RuntimeError("Gitleaks returned an invalid JSON report.")

        findings = []

        for finding in gitleaks_results:

            rule_id = finding.get(
                "RuleID",
                "Unknown rule"
            )

            file_name = finding.get(
                "File",
                "unknown file"
            )

            start_line = finding.get(
                "StartLine",
                "?"
            )

            findings.append({
                "severity": "CRITICAL",

                "title": (
                    "Potential secret detected: "
                    f"{rule_id}"
                ),

                "description": (
                    "A potential secret was detected "
                    f"in {file_name} at line "
                    f"{start_line}."
                ),

                "source": "Gitleaks",

                "rule_id": rule_id,

                "file": file_name,

                "line": start_line
            })

        return findings

    finally:

        shutil.rmtree(
            report_directory,
            ignore_errors=True
        )


# ============================================================
# Trivy Vulnerability Scanner
# ============================================================

def run_trivy_scan(repository_directory):
    """Run Trivy filesystem vulnerability scanning and normalize its findings."""
    report_directory = tempfile.mkdtemp(prefix="codeshield-trivy-")
    report_path = os.path.join(report_directory, "trivy-report.json")

    command = [
        TRIVY_PATH,
        "fs",
        "--scanners", "vuln",
        "--format", "json",
        "--output", report_path,
        repository_directory,
    ]

    try:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
        except FileNotFoundError as error:
            raise RuntimeError(
                "Trivy was not found. Make sure TRIVY_PATH is configured correctly. "
                f"Current value: {TRIVY_PATH}"
            ) from error
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("Trivy vulnerability scan timed out.") from error

        if result.returncode != 0:
            raise RuntimeError("Trivy vulnerability scan failed. Check server logs for details.")

        if not os.path.isfile(report_path):
            raise RuntimeError("Trivy did not generate a JSON report.")

        try:
            with open(report_path, "r", encoding="utf-8") as report_file:
                trivy_results = json.load(report_file)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as error:
            raise RuntimeError("Trivy returned an invalid JSON report.") from error

        if not isinstance(trivy_results, dict):
            raise RuntimeError("Trivy returned an unexpected JSON report format.")

        results = trivy_results.get("Results") or []
        if not isinstance(results, list):
            raise RuntimeError("Trivy returned an unexpected vulnerability report format.")
        findings = []
        for target in results:
            if not isinstance(target, dict):
                continue

            target_name = target.get("Target", "unknown target")
            vulnerabilities = target.get("Vulnerabilities") or []
            if not isinstance(vulnerabilities, list):
                continue

            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    continue

                severity = str(vulnerability.get("Severity") or "UNKNOWN").upper()
                if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                    severity = "UNKNOWN"

                vulnerability_id = vulnerability.get("VulnerabilityID", "Unknown vulnerability")
                package_name = vulnerability.get("PkgName", "Unknown package")
                installed_version = vulnerability.get("InstalledVersion", "Unknown")
                fixed_version = vulnerability.get("FixedVersion") or ""
                title = vulnerability.get("Title") or vulnerability_id
                description = vulnerability.get("Description") or (
                    f"{package_name} {installed_version} has vulnerability {vulnerability_id}."
                )

                findings.append({
                    "severity": severity,
                    "title": title,
                    "description": description,
                    "source": "Trivy",
                    "rule_id": vulnerability_id,
                    "file": target_name,
                    "line": None,
                    "package": package_name,
                    "installed_version": installed_version,
                    "fixed_version": fixed_version,
                })

        return findings
    finally:
        # Includes scanner-not-found and timeout failures so temporary reports do not leak.
        shutil.rmtree(report_directory, ignore_errors=True)


# ============================================================
# Security Score
# ============================================================

def calculate_security_score(findings):
    """
    Calculate a security score from 0-100.

    Each finding reduces the remaining score by a percentage:

        CRITICAL = 25%
        HIGH     = 15%
        MEDIUM   = 7%
        LOW      = 2%
    """

    score = 100

    severity_penalty_percentages = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 7,
        "LOW": 2
    }

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity", "UNKNOWN")).upper()
        penalty = severity_penalty_percentages.get(severity, 0)
        score *= (100 - penalty) / 100

    return max(0, min(100, int(score + 0.5)))


# ============================================================
# Finding Statistics
# ============================================================

def calculate_finding_statistics(findings):
    """
    Return finding counts grouped by severity and scanner.
    """

    statistics = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0,
        "gitleaks": 0,
        "trivy": 0
    }

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = str(
            finding.get(
                "severity",
                "UNKNOWN"
            )
        ).lower()

        if severity in statistics:
            statistics[severity] += 1

        source = str(
            finding.get(
                "source",
                ""
            )
        ).lower()

        if source == "gitleaks":
            statistics["gitleaks"] += 1

        elif source == "trivy":
            statistics["trivy"] += 1

    return statistics



# ============================================================
# Endpoint and Container Scanning
# ============================================================

def _is_public_destination(address):
    """Return True only for globally routable IP addresses."""
    if isinstance(address, str):
        try:
            address = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError:
            return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if isinstance(address, ipaddress.IPv6Address):
        # Do not allow transition/tunnelling ranges that can encode IPv4 targets.
        transition_ranges = (
            ipaddress.ip_network("64:ff9b::/96"),
            ipaddress.ip_network("64:ff9b:1::/48"),
            ipaddress.ip_network("2002::/16"),
            ipaddress.ip_network("2001::/32"),
        )
        if any(address in network for network in transition_ranges):
            return False
    return bool(
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
    )


def _resolve_public_http_target(value):
    """Validate a public HTTP(S) URL and return its parsed URL plus a pinned IP.

    Every DNS answer must be globally routable. The selected address is later used
    directly for the socket connection so a second DNS lookup cannot rebind the
    target between validation and connection.
    """
    if not isinstance(value, str) or not value or len(value) > 2048:
        return None
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value):
        return None

    try:
        parsed = urlparse(value.strip())
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            return None
        if not parsed.hostname or parsed.username is not None or parsed.password is not None:
            return None
        if parsed.netloc.endswith(":"):
            return None
        port = parsed.port
        expected_port = 443 if scheme == "https" else 80
        if port not in (None, expected_port):
            return None

        host = parsed.hostname.rstrip(".").lower()
        if not host or "%" in host:
            return None
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".home.arpa", ".test", ".invalid", ".example")):
            return None

        is_ip_literal = False
        try:
            literal_address = ipaddress.ip_address(host)
            is_ip_literal = True
            addresses = [literal_address]
            connect_host = str(literal_address)
            certificate_host = str(literal_address)
        except ValueError:
            connect_host = host.encode("idna").decode("ascii")
            certificate_host = connect_host
            results = socket.getaddrinfo(
                connect_host,
                port or expected_port,
                type=socket.SOCK_STREAM,
            )
            addresses = []
            for result in results:
                sockaddr = result[4]
                addresses.append(ipaddress.ip_address(sockaddr[0].split("%", 1)[0]))

        if not addresses or any(not _is_public_destination(address) for address in addresses):
            return None

        # Normalize the authority so Host and TLS SNI use the validated hostname.
        if is_ip_literal and isinstance(addresses[0], ipaddress.IPv6Address):
            authority_host = f"[{connect_host}]"
        else:
            authority_host = connect_host
        if port is not None:
            authority = f"{authority_host}:{port}"
        else:
            authority = authority_host
        normalized_path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
        normalized_query = quote(parsed.query, safe="/?%:@!$&'()*+,;=-._~")
        path = f"{normalized_path}?{normalized_query}" if normalized_query else normalized_path
        safe_url = parsed._replace(
            netloc=authority,
            path=normalized_path,
            query=normalized_query,
            fragment="",
        ).geturl()
        return {
            "parsed": parsed,
            "scheme": scheme,
            "host": certificate_host,
            "port": port or expected_port,
            "connect_ip": str(addresses[0]),
            "authority": authority,
            "path": path,
            "url": safe_url,
        }
    except (ValueError, OSError, socket.gaierror, UnicodeError):
        return None


def validate_public_http_url(value):
    """Return a normalized public HTTP(S) URL, or None when it is not safe."""
    validated = _resolve_public_http_target(value)
    return validated["url"] if validated else None


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that connects to a previously validated numeric IP."""
    def __init__(self, host, port, connect_ip, timeout=8):
        super().__init__(host, port=port, timeout=timeout)
        self.connect_ip = connect_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self.connect_ip, self.port),
            self.timeout,
            self.source_address,
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to an IP while retaining hostname TLS checks."""
    def __init__(self, host, port, connect_ip, timeout=8):
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self.connect_ip = connect_ip

    def connect(self):
        raw_socket = socket.create_connection(
            (self.connect_ip, self.port),
            self.timeout,
            self.source_address,
        )
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


def _make_pinned_connection(validated, timeout=8):
    connection_class = _PinnedHTTPSConnection if validated["scheme"] == "https" else _PinnedHTTPConnection
    return connection_class(
        validated["host"],
        validated["port"],
        validated["connect_ip"],
        timeout=timeout,
    )


def run_endpoint_scan(target):
    """Check a public web endpoint without following redirects or re-resolving DNS."""
    validated = _resolve_public_http_target(target)
    if validated is None:
        raise ValueError("Endpoint must be a public HTTP(S) URL on a standard web port. Private, local, and non-public destinations are blocked.")

    connection = _make_pinned_connection(validated, timeout=8)
    try:
        connection.request(
            "GET",
            validated["path"],
            headers={
                "Host": validated["authority"],
                "User-Agent": "CodeShield-Scanner/1.0",
                "Accept": "*/*",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        status = response.status
        headers = response.headers
        # Read a small prefix only; redirects are returned, never followed.
        response.read(4096)
    except (TimeoutError, OSError, http.client.HTTPException, ssl.SSLError, UnicodeError) as error:
        raise RuntimeError(f"Endpoint request failed: {type(error).__name__}. Check the URL and try again.") from error
    finally:
        connection.close()

    findings = []
    checks = [
        ("Strict-Transport-Security", "HIGH", "HTTP Strict Transport Security is missing", "Enable HSTS on HTTPS sites to help prevent protocol downgrade attacks."),
        ("Content-Security-Policy", "MEDIUM", "Content Security Policy is missing", "Add a suitable Content-Security-Policy to reduce the impact of some injection attacks."),
        ("X-Content-Type-Options", "LOW", "X-Content-Type-Options is missing", "Set X-Content-Type-Options: nosniff."),
        ("Referrer-Policy", "LOW", "Referrer Policy is missing", "Set a Referrer-Policy appropriate for the application."),
        ("Permissions-Policy", "LOW", "Permissions Policy is missing", "Restrict browser features that the application does not need."),
    ]
    for header, severity, title, description in checks:
        if not headers.get(header):
            if header == "Strict-Transport-Security" and validated["scheme"] != "https":
                continue
            findings.append({
                "severity": severity,
                "title": title,
                "description": description,
                "source": "HTTP",
                "rule_id": f"missing-{header.lower()}",
                "file": validated["authority"],
            })
    if status >= 500:
        findings.append({
            "severity": "MEDIUM",
            "title": "Endpoint returned a server error",
            "description": f"The endpoint responded with HTTP {status}. Review server logs and error handling.",
            "source": "HTTP",
            "rule_id": "http-server-error",
            "file": validated["authority"],
        })
    elif 300 <= status < 400:
        findings.append({
            "severity": "INFO",
            "title": "Endpoint returned a redirect",
            "description": "The redirect was not followed. Scan the destination separately after confirming it is an authorized public endpoint.",
            "source": "HTTP",
            "rule_id": "http-redirect-not-followed",
            "file": validated["authority"],
        })
    return findings


def validate_container_reference(value):
    """Conservative validation for Docker/OCI image references passed to Trivy."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > 512 or value.startswith("-") or any(ch.isspace() for ch in value):
        return None
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]*", value):
        return None
    if value.count("@") > 1 or value.endswith(":") or "//" in value:
        return None
    return value


def run_trivy_image_scan(image_reference):
    """Run Trivy against a container image and normalize vulnerability results."""
    image_reference = validate_container_reference(image_reference)
    if image_reference is None:
        raise ValueError("Enter a valid container image reference, for example nginx:1.27 or ghcr.io/owner/image:tag.")

    temporary_directory = tempfile.mkdtemp(prefix="codeshield-image-")
    report_path = os.path.join(temporary_directory, "trivy-image.json")
    command = [
        TRIVY_PATH, "image", "--scanners", "vuln",
        "--format", "json", "--output", report_path,
        "--timeout", "5m", image_reference,
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=360, check=False,
        )
        if result.returncode != 0:
            raise RuntimeError("Container scan failed. Check server logs for details.")
        try:
            with open(report_path, "r", encoding="utf-8") as report_file:
                report = json.load(report_file)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as error:
            raise RuntimeError("Trivy did not produce a valid image scan report.") from error

        if not isinstance(report, dict):
            raise RuntimeError("Trivy returned an invalid image scan report.")
        results = report.get("Results") or []
        if not isinstance(results, list):
            raise RuntimeError("Trivy returned an invalid image scan report.")
        findings = []
        for item in results:
            if not isinstance(item, dict):
                continue
            target = item.get("Target", "container image")
            vulnerabilities = item.get("Vulnerabilities") or []
            if not isinstance(vulnerabilities, list):
                continue
            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue
                findings.append({
                    "severity": str(vuln.get("Severity") or "UNKNOWN").upper(),
                    "title": vuln.get("Title") or vuln.get("VulnerabilityID") or "Container vulnerability",
                    "description": vuln.get("Description") or vuln.get("Title") or "No description provided by Trivy.",
                    "source": "Trivy",
                    "rule_id": vuln.get("VulnerabilityID", ""),
                    "file": target,
                    "package": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "references": (vuln.get("References") or [])[:5],
                })
        return findings
    except FileNotFoundError as error:
        raise RuntimeError("Trivy was not found. Configure TRIVY_PATH.") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Container scan timed out after 6 minutes.") from error
    finally:
        shutil.rmtree(temporary_directory, ignore_errors=True)



def run_trivy_config_scan(repository_directory):
    """Scan repository infrastructure/configuration files with Trivy."""
    report_directory = tempfile.mkdtemp(prefix="codeshield-config-")
    report_path = os.path.join(report_directory, "trivy-config.json")
    command = [
        TRIVY_PATH, "config", "--format", "json",
        "--output", report_path, repository_directory,
    ]
    try:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=300, check=False)
        except FileNotFoundError as error:
            raise RuntimeError("Trivy was not found. Configure TRIVY_PATH.") from error
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("Trivy configuration scan timed out.") from error
        if result.returncode != 0:
            raise RuntimeError("Trivy configuration scan failed. Check server logs for details.")
        try:
            with open(report_path, "r", encoding="utf-8") as handle:
                report = json.load(handle)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as error:
            raise RuntimeError("Trivy did not produce a valid configuration report.") from error
        if not isinstance(report, dict):
            raise RuntimeError("Trivy returned an invalid configuration report.")
        results = report.get("Results") or []
        if not isinstance(results, list):
            raise RuntimeError("Trivy returned an invalid configuration report.")
        findings = []
        for item in results:
            if not isinstance(item, dict):
                continue
            target = item.get("Target", "unknown target")
            misconfigurations = item.get("Misconfigurations") or []
            if not isinstance(misconfigurations, list):
                continue
            for misconfig in misconfigurations:
                if not isinstance(misconfig, dict):
                    continue
                severity = str(misconfig.get("Severity") or "UNKNOWN").upper()
                if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                    severity = "UNKNOWN"
                cause = misconfig.get("CauseMetadata") or {}
                if not isinstance(cause, dict):
                    cause = {}
                findings.append({
                    "severity": severity,
                    "title": misconfig.get("Title") or misconfig.get("ID") or "Infrastructure misconfiguration",
                    "description": misconfig.get("Description") or misconfig.get("Message") or "Review this configuration finding.",
                    "source": "Trivy",
                    "rule_id": misconfig.get("ID", ""),
                    "file": target,
                    "line": (cause.get("StartLine") or None),
                    "references": (misconfig.get("References") or [])[:5],
                })
        return findings
    finally:
        shutil.rmtree(report_directory, ignore_errors=True)


# ============================================================
# Security Scanner
# ============================================================

def deduplicate_findings(findings):
    """Remove exact duplicate findings while retaining distinct report details."""
    unique = []
    seen = set()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = json.dumps(finding, sort_keys=True, separators=(",", ":"), default=str)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def run_security_scan(
    target,
    scan_type,
    repository_directory=None
):
    """
    Run the appropriate security scanners.
    """

    findings = []

    # --------------------------------------------------------
    # Repository Scan
    # --------------------------------------------------------

    if scan_type == "repo":

        if repository_directory is None:

            raise ValueError(
                "Repository directory is required "
                "for repository scans."
            )

        # Real Gitleaks secret scan
        gitleaks_findings = run_gitleaks_scan(
            repository_directory
        )

        # Real Trivy vulnerability scan
        trivy_findings = run_trivy_scan(repository_directory)
        config_findings = run_trivy_config_scan(repository_directory)

        # Combine secret, dependency, and infrastructure/configuration findings.
        findings = gitleaks_findings + trivy_findings + config_findings

    # --------------------------------------------------------
    # Endpoint Scan (real HTTP security-header checks)
    # --------------------------------------------------------
    elif scan_type == "endpoint":
        findings = run_endpoint_scan(target)

    # --------------------------------------------------------
    # Container Scan (real Trivy image scan)
    # --------------------------------------------------------
    elif scan_type == "container":
        findings = run_trivy_image_scan(target)

    findings = deduplicate_findings(findings)
    score = calculate_security_score(findings)
    statistics = calculate_finding_statistics(findings)

    return {

        "target": target,

        "scan_type": scan_type,

        "score": score,

        "findings": findings,

        "finding_count": len(findings),

        "statistics": statistics,

        "timestamp": datetime.now(
            timezone.utc
        ).isoformat()
    }


# ============================================================
# Request hardening and routes
# ============================================================

@app.after_request
def add_security_headers(response):
    """Apply baseline browser security headers to dashboard and API responses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    if request.path == "/api/scan":
        response.headers["Cache-Control"] = "no-store"
    if os.getenv("ENVIRONMENT", ENVIRONMENT).strip().lower() == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify({"error": "Request body exceeds the 1 MiB limit."}), 413


def _check_scan_api_access():
    """Require a configured token in production and enforce a per-IP rate limit."""
    try:
        limit = max(1, int(os.getenv("SCAN_RATE_LIMIT_REQUESTS", "60")))
        window = max(1, int(os.getenv("SCAN_RATE_LIMIT_WINDOW_SECONDS", "60")))
    except ValueError:
        limit, window = 60, 60
    now = time.monotonic()
    client_ip = request.remote_addr or "unknown"
    with _RATE_LIMIT_LOCK:
        if len(_RATE_LIMIT_BUCKETS) > 1000:
            for known_ip, history in list(_RATE_LIMIT_BUCKETS.items()):
                while history and now - history[0] >= window:
                    history.popleft()
                if not history:
                    _RATE_LIMIT_BUCKETS.pop(known_ip, None)
        bucket = _RATE_LIMIT_BUCKETS[client_ip]
        while bucket and now - bucket[0] >= window:
            bucket.popleft()
        if len(bucket) >= limit:
            response = jsonify({"error": "Scan rate limit exceeded. Please wait before trying again."})
            response.status_code = 429
            response.headers["Retry-After"] = str(max(1, int(window - (now - bucket[0]))))
            return response
        bucket.append(now)

    configured_token = os.getenv("SCAN_API_TOKEN", "").strip()
    production_mode = os.getenv("ENVIRONMENT", ENVIRONMENT).strip().lower() == "production"
    if production_mode and not configured_token:
        return jsonify({"error": "Scan API authentication is not configured."}), 503
    if production_mode and len(configured_token) < 32:
        return jsonify({"error": "The production scan API token must contain at least 32 characters."}), 503
    if configured_token:
        supplied_token = request.headers.get("X-Scan-Token", "")
        if not hmac.compare_digest(supplied_token.encode("utf-8"), configured_token.encode("utf-8")):
            return jsonify({"error": "A valid X-Scan-Token header is required."}), 401
    return None


@app.route("/")
def home():

    uptime = int(
        time.time() - START_TIME
    )

    return render_template(
        "index.html",

        version=VERSION,

        environment=ENVIRONMENT,

        uptime=uptime
    )


@app.route("/health")
def health():

    return jsonify({

        "status": "healthy",

        "version": VERSION,

        "environment": ENVIRONMENT

    }), 200


@app.route("/api/info")
def info():

    return jsonify({

        "application": "CodeShield",

        "version": VERSION,

        "environment": ENVIRONMENT,

        "status": "running",

        "uptime_seconds": int(
            time.time() - START_TIME
        ),

        "timestamp": datetime.now(
            timezone.utc
        ).isoformat()

    })


# ============================================================
# GitHub Actions Pipeline Status
# ============================================================

load_dotenv()

GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY", "arunava-12/CodeShield").strip()
GITHUB_BRANCH = os.getenv("GITHUB_BRANCH", "codeshield-dev").strip()
GITHUB_API_TOKEN = os.getenv("GITHUB_API_TOKEN", "").strip()
GITHUB_API_BASE = "https://api.github.com"


def _github_api_json(path):
    """Fetch a GitHub REST API JSON resource without exposing credentials to clients."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", GITHUB_REPOSITORY):
        raise ValueError("GITHUB_REPOSITORY must use owner/repository format.")
    request_headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "CodeShield-Pipeline-Dashboard",
    }
    if GITHUB_API_TOKEN:
        request_headers["Authorization"] = f"Bearer {GITHUB_API_TOKEN}"
    api_request = urllib.request.Request(
        f"{GITHUB_API_BASE}{path}", headers=request_headers, method="GET"
    )
    with urllib.request.urlopen(api_request, timeout=8) as response:
        return json.loads(response.read(1024 * 1024).decode("utf-8"))


def _normalize_pipeline_status(status, conclusion=None):
    """Convert GitHub workflow/job/step state into a small dashboard vocabulary."""
    if status in {"queued", "waiting", "pending", "requested", "in_progress"}:
        return "running" if status == "in_progress" else "queued"
    if status == "completed":
        if conclusion == "success":
            return "passed"
        if conclusion in {"failure", "timed_out", "action_required"}:
            return "failed"
        if conclusion == "cancelled":
            return "cancelled"
        if conclusion == "skipped":
            return "skipped"
    return "unknown"


def _find_step_status(jobs, job_name, step_name):
    for job in jobs:
        if job.get("name") != job_name:
            continue
        for step in job.get("steps", []):
            if step.get("name") == step_name:
                return _normalize_pipeline_status(step.get("status"), step.get("conclusion"))
    return "unknown"


def _workflow_run(path):
    payload = _github_api_json(path)
    runs = payload.get("workflow_runs", [])
    return runs[0] if runs else None


@app.route("/api/pipeline")
def pipeline_status():
    """Return live GitHub Actions statuses for the dashboard's pipeline cards."""
    repository_path = f"/repos/{GITHUB_REPOSITORY}"
    try:
        ci_run = _workflow_run(
            f"{repository_path}/actions/workflows/cloudsentinel-ci.yml/runs?branch={quote(GITHUB_BRANCH)}&per_page=1"
        )
        deploy_run = _workflow_run(
            f"{repository_path}/actions/workflows/deploy.yml/runs?branch=main&per_page=1"
        )
        if ci_run:
            jobs_payload = _github_api_json(
                f"{repository_path}/actions/runs/{int(ci_run['id'])}/jobs?per_page=100"
            )
            jobs = jobs_payload.get("jobs", [])
            secret_status = next((
                _normalize_pipeline_status(job.get("status"), job.get("conclusion"))
                for job in jobs if job.get("name") == "Security Scan"
            ), "unknown")
            docker_status = _find_step_status(jobs, "Test Application", "Build Docker image")
            test_status = _find_step_status(jobs, "Test Application", "Run tests")
            image_status = _find_step_status(jobs, "Test Application", "Scan Docker image")
            ci_url = ci_run.get("html_url")
            ci_updated = ci_run.get("updated_at") or ci_run.get("created_at")
        else:
            secret_status = docker_status = test_status = image_status = "not_run"
            ci_url = None
            ci_updated = None

        deploy_status = (
            _normalize_pipeline_status(deploy_run.get("status"), deploy_run.get("conclusion"))
            if deploy_run else "not_run"
        )
        return jsonify({
            "repository": GITHUB_REPOSITORY,
            "branch": GITHUB_BRANCH,
            "available": True,
            "updated_at": ci_updated,
            "workflow_url": ci_url,
            "deployment_url": deploy_run.get("html_url") if deploy_run else None,
            "stages": [
                {"id": "secret-scan", "label": "Secret scan", "status": secret_status},
                {"id": "docker-build", "label": "Docker build", "status": docker_status},
                {"id": "automated-tests", "label": "Automated tests", "status": test_status},
                {"id": "image-scan", "label": "Image scan", "status": image_status},
                {"id": "ec2-deployment", "label": "EC2 deployment", "status": deploy_status},
            ],
        })
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        app.logger.exception("Unable to retrieve GitHub Actions status")
        return jsonify({
            "available": False,
            "error": "GitHub Actions status is temporarily unavailable.",
            "repository": GITHUB_REPOSITORY,
            "branch": GITHUB_BRANCH,
            "stages": [
                {"id": stage_id, "label": label, "status": "unknown"}
                for stage_id, label in [
                    ("secret-scan", "Secret scan"),
                    ("docker-build", "Docker build"),
                    ("automated-tests", "Automated tests"),
                    ("image-scan", "Image scan"),
                    ("ec2-deployment", "EC2 deployment"),
                ]
            ],
        }), 502


# ============================================================
# Security Scan API
# ============================================================

@app.route(
    "/api/scan",
    methods=["POST"]
)
def scan():

    access_error = _check_scan_api_access()
    if access_error is not None:
        return access_error

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400

    target = str(
        data.get(
            "target",
            ""
        )
    ).strip()

    scan_type = str(
        data.get(
            "scan_type",
            ""
        )
    ).strip().lower()

    # --------------------------------------------------------
    # Validate target
    # --------------------------------------------------------

    if not target:

        return jsonify({

            "error": "Target is required."

        }), 400

    if len(target) > 2048:
        return jsonify({
            "error": "Target must be 2048 characters or fewer."
        }), 400

    # --------------------------------------------------------
    # Validate scan type
    # --------------------------------------------------------

    allowed_scan_types = {
        "repo",
        "container",
        "endpoint"
    }

    if scan_type not in allowed_scan_types:

        return jsonify({

            "error": (
                "Invalid scan type. "
                "Use repo, container, or endpoint."
            )

        }), 400

    # --------------------------------------------------------
    # Repository scan
    # --------------------------------------------------------

    if scan_type == "repo":

        temporary_directory = None

        try:

            # 1. Clone repository
            repository_result = (
                clone_repository(target)
            )

            temporary_directory = (
                repository_result[
                    "temporary_directory"
                ]
            )

            repository_directory = (
                repository_result[
                    "repository_directory"
                ]
            )

            # 2. Run Gitleaks + Trivy
            scan_result = run_security_scan(

                target,

                scan_type,

                repository_directory

            )

            # Do not expose internal filesystem paths
            # to the browser.

            repository_result.pop(
                "repository_directory",
                None
            )

            repository_result.pop(
                "temporary_directory",
                None
            )

            scan_result[
                "repository"
            ] = repository_result

            return jsonify(
                scan_result
            ), 200

        except ValueError as error:

            return jsonify({

                "error": str(error)

            }), 400

        except RuntimeError as error:

            return jsonify({

                "error": str(error)

            }), 500

        except Exception:
            app.logger.exception("Repository scan failed unexpectedly")
            return jsonify({"error": "The repository scan failed unexpectedly. Check server logs for details."}), 500

        finally:

            # Always remove cloned repository.
            if temporary_directory:

                shutil.rmtree(
                    temporary_directory,
                    ignore_errors=True
                )

    # --------------------------------------------------------
    # Container / Endpoint
    # --------------------------------------------------------

    try:

        return jsonify(

            run_security_scan(

                target,

                scan_type

            )

        ), 200

    except ValueError as error:

        return jsonify({

            "error": str(error)

        }), 400

    except RuntimeError as error:

        return jsonify({

            "error": str(error)

        }), 500

    except Exception:
        app.logger.exception("Scan failed unexpectedly")
        return jsonify({"error": "The scan failed unexpectedly. Check server logs for details."}), 500


# ============================================================
# Application Entry Point
# ============================================================

if __name__ == "__main__":

    app.run(

        host="0.0.0.0",

        port=5000

    )
