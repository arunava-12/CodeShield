from flask import Flask, jsonify, render_template, request

from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPRedirectHandler
import ipaddress
import socket

import json
import os
import re
import shutil
import subprocess
import tempfile
import time


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024  # Limit scan API request bodies to 1 MiB.


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
        "--depth",
        "1",
        clone_url,
        repository_directory
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
            "Repository clone timed out."
        )

    if result.returncode != 0:

        error_message = result.stderr.strip()

        shutil.rmtree(
            temporary_directory,
            ignore_errors=True
        )

        if not error_message:
            error_message = "Git clone failed."

        raise RuntimeError(
            error_message
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

            error_message = (
                result.stderr.strip()
            )

            if not error_message:
                error_message = (
                    "Gitleaks scan failed."
                )

            raise RuntimeError(
                error_message
            )

        # Gitleaks normally creates the JSON report
        # even when there are no findings.

        if not os.path.exists(
            report_path
        ):

            gitleaks_results = []

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

            except json.JSONDecodeError:

                raise RuntimeError(
                    "Gitleaks returned an invalid "
                    "JSON report."
                )

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
            error_message = result.stderr.strip() or "Trivy vulnerability scan failed."
            raise RuntimeError(error_message)

        if not os.path.isfile(report_path):
            raise RuntimeError("Trivy did not generate a JSON report.")

        try:
            with open(report_path, "r", encoding="utf-8") as report_file:
                trivy_results = json.load(report_file)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise RuntimeError("Trivy returned an invalid JSON report.") from error

        if not isinstance(trivy_results, dict):
            raise RuntimeError("Trivy returned an unexpected JSON report format.")

        findings = []
        for target in trivy_results.get("Results") or []:
            if not isinstance(target, dict):
                continue

            target_name = target.get("Target", "unknown target")
            vulnerabilities = target.get("Vulnerabilities") or []

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

    Penalties:

        CRITICAL = 25
        HIGH     = 15
        MEDIUM   = 7
        LOW      = 2
    """

    score = 100

    severity_penalties = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 7,
        "LOW": 2
    }

    for finding in findings:

        severity = finding.get(
            "severity",
            "LOW"
        )

        score -= severity_penalties.get(
            severity,
            0
        )

    return max(
        0,
        min(
            100,
            score
        )
    )


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

class _NoRedirectHandler(HTTPRedirectHandler):
    """Do not follow redirects; each redirect target must be reviewed separately."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_public_http_url(value):
    """Validate an HTTP(S) target and reject local/private network destinations."""
    if not isinstance(value, str) or len(value) > 2048:
        return None
    try:
        parsed = urlparse(value.strip())
        if parsed.scheme.lower() not in {"http", "https"}:
            return None
        if not parsed.hostname or parsed.username or parsed.password:
            return None
        if parsed.port not in (None, 80, 443):
            # Restrict scanning to conventional web ports.
            return None
        if parsed.scheme.lower() == "https" and parsed.port not in (None, 443):
            return None
        if parsed.scheme.lower() == "http" and parsed.port not in (None, 80):
            return None
        host = parsed.hostname.rstrip(".").lower()
        if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
            return None
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            addresses = [
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
            ]
        if not addresses or any(
            not addr.is_global or addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved
            for addr in addresses
        ):
            return None
        return parsed.geturl()
    except (ValueError, OSError, socket.gaierror):
        return None


def run_endpoint_scan(target):
    """Check a public web endpoint's availability and common security headers."""
    safe_url = validate_public_http_url(target)
    if safe_url is None:
        raise ValueError("Endpoint must be a public HTTP(S) URL on a standard web port. Private, local, and non-public destinations are blocked.")

    request = Request(
        safe_url,
        headers={"User-Agent": "CodeShield-Scanner/1.0", "Accept": "*/*"},
        method="GET",
    )
    opener = build_opener(_NoRedirectHandler)
    try:
        with opener.open(request, timeout=8) as response:
            status = response.status
            headers = response.headers
            # Read only a small prefix so endpoints cannot force large downloads.
            response.read(4096)
    except HTTPError as error:
        # HTTP errors still carry useful response headers and indicate a reachable endpoint.
        status = error.code
        headers = error.headers
    except (URLError, TimeoutError, OSError) as error:
        raise RuntimeError(f"Endpoint request failed: {type(error).__name__}. Check the URL and try again.") from error

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
            # HSTS is meaningful only over HTTPS.
            if header == "Strict-Transport-Security" and not safe_url.lower().startswith("https://"):
                continue
            findings.append({
                "severity": severity,
                "title": title,
                "description": description,
                "source": "HTTP",
                "rule_id": f"missing-{header.lower()}",
                "file": urlparse(safe_url).netloc,
            })
    if status >= 500:
        findings.append({
            "severity": "MEDIUM",
            "title": "Endpoint returned a server error",
            "description": f"The endpoint responded with HTTP {status}. Review server logs and error handling.",
            "source": "HTTP",
            "rule_id": "http-server-error",
            "file": urlparse(safe_url).netloc,
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
            detail = (result.stderr or result.stdout or "Trivy could not scan this image.").strip()
            raise RuntimeError(f"Container scan failed: {detail[-1200:]}")
        try:
            with open(report_path, "r", encoding="utf-8") as report_file:
                report = json.load(report_file)
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError("Trivy did not produce a valid image scan report.") from error

        findings = []
        for item in report.get("Results") or []:
            target = item.get("Target", "container image")
            for vuln in item.get("Vulnerabilities") or []:
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
            raise RuntimeError((result.stderr or "Trivy configuration scan failed.")[-1200:])
        try:
            with open(report_path, "r", encoding="utf-8") as handle:
                report = json.load(handle)
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError("Trivy did not produce a valid configuration report.") from error
        findings = []
        for item in report.get("Results") or []:
            target = item.get("Target", "unknown target")
            for misconfig in item.get("Misconfigurations") or []:
                severity = str(misconfig.get("Severity") or "UNKNOWN").upper()
                if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                    severity = "UNKNOWN"
                cause = misconfig.get("CauseMetadata") or {}
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

    score = calculate_security_score(
        findings
    )

    statistics = calculate_finding_statistics(
        findings
    )

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
# Routes
# ============================================================

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
# Security Scan API
# ============================================================

@app.route(
    "/api/scan",
    methods=["POST"]
)
def scan():

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


# ============================================================
# Application Entry Point
# ============================================================

if __name__ == "__main__":

    app.run(

        host="0.0.0.0",

        port=5000

    )

