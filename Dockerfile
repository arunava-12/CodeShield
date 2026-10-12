FROM python:3.12-slim

# Install Git, HTTPS certificates, curl and tar
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        curl \
        tar \
    && rm -rf /var/lib/apt/lists/*

# Pin scanner versions for reproducible builds
ARG GITLEAKS_VERSION=8.30.1
ARG TRIVY_VERSION=0.75.0

# Install Gitleaks and Trivy for Linux AMD64
RUN set -eux; \
    curl -fsSL \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
      -o /tmp/gitleaks.tar.gz; \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks; \
    rm /tmp/gitleaks.tar.gz; \
    curl -fsSL \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
      -o /tmp/trivy.tar.gz; \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy; \
    rm /tmp/trivy.tar.gz

WORKDIR /app

# Create an unprivileged application user
RUN useradd --create-home --shell /bin/bash appuser

# Install production dependencies
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application and tests
COPY app/ ./app/
COPY tests/ ./tests/
COPY app/requirements-dev.txt .

# Give the application user ownership of application files
RUN chown -R appuser:appuser /app

ENV APP_VERSION=1.0.0
ENV ENVIRONMENT=development
ENV PYTHONPATH=/app

USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

CMD ["python", "app/app.py"]
