# CodeShield update summary

This ZIP contains a coordinated update to the source project. It deliberately does not include `.git`, `.terraform`, Terraform state, real `terraform.tfvars`, plan files, local databases, caches, or logs.

## Included changes

- Dashboard updates: API token field, consistent scan results, recent scan history, JSON/HTML report downloads, and an optional LLM evaluation panel.
- API hardening: optional `X-API-Key` / Bearer authentication; protected production routes fail closed without a 32+ character token; request-size limits; security headers; per-process scan rate limiting; target validation; endpoint DNS resolution checks and IP pinning; no automatic redirects.
- Scanner reliability: scanner timeouts, bounded repository file count, normalized severities, duplicate finding handling, clearer API errors, and consistent `success`, `scan_id`, score, and statistics fields.
- Reports and history: SQLite-backed scan records, newest 1,000 scans retained, JSON and HTML report endpoints.
- LLM integration: optional proxy to the existing `LLM-BenchMarking-Platform` FastAPI endpoints `/api/models`, `/api/ask`, and `/api/progress/{job_id}`. Configure `LLM_BENCHMARK_API_URL` to enable it.
- Runtime: Gunicorn production WSGI server, non-root Docker user, persistent-data path, and container health check.
- CI/CD: Gitleaks, pip-audit, pytest, Docker smoke test, Trivy image scan, and Terraform validation. Regular CI does not deploy to AWS.
- Deployment and infrastructure: manual-only GitHub deployment workflow, OIDC trust scoped to the `production` environment, no inbound SSH rule, SSM token retrieval, Caddy HTTPS termination, CloudWatch application/proxy logs and EC2 alarms.
- Documentation and safe configuration examples updated.

## Checks performed in the editing environment

- Python syntax compilation: passed.
- Dashboard JavaScript syntax (`node --check`): passed.
- GitHub Actions YAML parsing: passed.
- Duplicate HTML element IDs: none found.
- Full pytest suite, Docker build, and Terraform validation could not be executed here because this environment has no Flask dependency installed and network access is unavailable to install it; Docker and Terraform CLIs are also unavailable here. The updated CI workflow is configured to run those checks in GitHub Actions.

## Before production use

1. Install the development dependencies and run `pytest -q`.
2. Build and test the Docker image locally.
3. Run `terraform fmt -check -recursive`, `terraform init -backend=false`, and `terraform validate`.
4. Review `terraform plan` against your own existing state before any apply. This ZIP intentionally excludes state and real variable files.
5. Create the SSM Parameter Store `SecureString` `/codeshield/scan-api-token`, set GitHub deployment variables, and configure the GitHub `production` environment to allow only `main` and require reviewer approval.
6. Do not run the manual deployment workflow until you explicitly intend to deploy and have reviewed potential AWS charges.
