from flask import Flask, jsonify, render_template, request

from datetime import datetime, timezone
from urllib.parse import urlparse

import json
import os
import re
import shutil
import subprocess
import tempfile
import time


app = Flask(__name__)


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
    if parsed.netloc.lower() != "github.com":
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
    """
    Run Trivy filesystem vulnerability scanning.

    Only vulnerability scanning is enabled because Gitleaks
    is responsible for secret detection.

    Returns normalized CodeShield findings.
    """

    report_directory = tempfile.mkdtemp(
        prefix="codeshield-trivy-"
    )

    report_path = os.path.join(
        report_directory,
        "trivy-report.json"
    )

    command = [
        TRIVY_PATH,
        "fs",

        "--scanners",
        "vuln",

        "--format",
        "json",

        "--output",
        report_path,

        "--no-progress",

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

        raise RuntimeError(
            "Trivy was not found.\n\n"
            "Make sure TRIVY_PATH is configured "
            "correctly.\n\n"
            f"Current value: {TRIVY_PATH}"
        )

    except subprocess.TimeoutExpired:

        raise RuntimeError(
            "Trivy vulnerability scan timed out."
        )

    try:

        if result.returncode != 0:

            error_message = (
                result.stderr.strip()
            )

            if not error_message:
                error_message = (
                    "Trivy vulnerability scan failed."
                )

            raise RuntimeError(
                error_message
            )

        if not os.path.exists(
            report_path
        ):

            raise RuntimeError(
                "Trivy did not generate a JSON report."
            )

        try:

            with open(
                report_path,
                "r",
                encoding="utf-8"
            ) as report_file:

                trivy_results = json.load(
                    report_file
                )

        except json.JSONDecodeError:

            raise RuntimeError(
                "Trivy returned an invalid JSON report."
            )

        findings = []

        for target in trivy_results.get(
            "Results",
            []
        ):

            target_name = target.get(
                "Target",
                "unknown target"
            )

            vulnerabilities = target.get(
                "Vulnerabilities",
                []
            ) or []

            for vulnerability in vulnerabilities:

                severity = str(
                    vulnerability.get(
                        "Severity",
                        "UNKNOWN"
                    )
                ).upper()

                # CodeShield currently supports
                # CRITICAL / HIGH / MEDIUM / LOW.
                if severity not in {
                    "CRITICAL",
                    "HIGH",
                    "MEDIUM",
                    "LOW"
                }:
                    severity = "LOW"

                vulnerability_id = (
                    vulnerability.get(
                        "VulnerabilityID",
                        "Unknown vulnerability"
                    )
                )

                package_name = (
                    vulnerability.get(
                        "PkgName",
                        "Unknown package"
                    )
                )

                installed_version = (
                    vulnerability.get(
                        "InstalledVersion",
                        "Unknown"
                    )
                )

                fixed_version = (
                    vulnerability.get(
                        "FixedVersion",
                        ""
                    )
                )

                title = vulnerability.get(
                    "Title",
                    vulnerability_id
                )

                description = vulnerability.get(
                    "Description",
                    ""
                )

                findings.append({

                    "severity": severity,

                    "title": title,

                    "description": (
                        description
                        if description
                        else (
                            f"{package_name} "
                            f"{installed_version} "
                            f"has vulnerability "
                            f"{vulnerability_id}."
                        )
                    ),

                    "source": "Trivy",

                    "rule_id": vulnerability_id,

                    "file": target_name,

                    "line": None,

                    "package": package_name,

                    "installed_version": installed_version,

                    "fixed_version": fixed_version
                })

        return findings

    finally:

        shutil.rmtree(
            report_directory,
            ignore_errors=True
        )


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
        "gitleaks": 0,
        "trivy": 0
    }

    for finding in findings:

        severity = str(
            finding.get(
                "severity",
                "LOW"
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
        trivy_findings = run_trivy_scan(
            repository_directory
        )

        # Combine both scanners
        findings = (
            gitleaks_findings
            + trivy_findings
        )

    # --------------------------------------------------------
    # Endpoint Scan
    # --------------------------------------------------------

    elif scan_type == "endpoint":

        findings = [

            {
                "severity": "MEDIUM",

                "title": (
                    "Security headers should be reviewed"
                ),

                "description": (
                    "Review HTTP response headers such as "
                    "Content-Security-Policy, HSTS and "
                    "X-Content-Type-Options."
                ),

                "source": "HTTP"
            },

            {
                "severity": "LOW",

                "title": (
                    "Health endpoint is publicly discoverable"
                ),

                "description": (
                    "Consider whether detailed health "
                    "information should be publicly "
                    "accessible."
                ),

                "source": "HTTP"
            }

        ]

    # --------------------------------------------------------
    # Container Scan
    # --------------------------------------------------------

    elif scan_type == "container":

        findings = [

            {
                "severity": "HIGH",

                "title": (
                    "Critical CVEs should block releases"
                ),

                "description": (
                    "Configure the container security stage "
                    "to fail when critical vulnerabilities "
                    "are detected."
                ),

                "source": "Trivy"
            },

            {
                "severity": "MEDIUM",

                "title": (
                    "Generate a software bill of materials"
                ),

                "description": (
                    "Generate an SBOM for container images "
                    "to improve dependency visibility."
                ),

                "source": "Container"
            }

        ]

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

    data = request.get_json(
        silent=True
    ) or {}

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