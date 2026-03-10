# ============================================================
# Local AI DevSecOps Agent — Dockerfile
# Multi-stage build: builder installs deps, final is slim
# ============================================================

# ── Stage 1: Builder ─────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    unzip \
    wget \
    gnupg \
    lsb-release \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# ── Install Python dependencies ───────────────────────────────
COPY requirements.txt .
RUN pip install --prefix=/install --no-cache-dir \
    "colorama>=0.4.6" \
    "Jinja2>=3.1.2" \
    "boto3>=1.34.0" \
    "azure-identity>=1.15.0" \
    "azure-mgmt-resource>=23.0.0" \
    "google-cloud-resource-manager>=1.12.0" \
    "kubernetes>=28.1.0" \
    "hvac>=2.1.0" \
    "pydantic>=2.0.0" \
    "cryptography>=41.0.0"

# ── Install Terraform ─────────────────────────────────────────
ARG TERRAFORM_VERSION=1.7.5
RUN ARCH=$(dpkg --print-architecture) \
    && wget -q https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_${ARCH}.zip \
    -O /tmp/terraform.zip \
    && unzip /tmp/terraform.zip -d /tmp/terraform_bin \
    && chmod +x /tmp/terraform_bin/terraform

# ── Install Trivy ────────────────────────────────────────────
ARG TRIVY_VERSION=0.69.3
RUN wget -q https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz \
    -O /tmp/trivy.tar.gz \
    && tar -xzf /tmp/trivy.tar.gz -C /tmp \
    && chmod +x /tmp/trivy

# ── Install tfsec via official apt repo ───────────────────────
# tfsec is now maintained alongside trivy by Aqua Security
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
        | gpg --dearmor -o /usr/share/keyrings/aqua.gpg 2>/dev/null || true \
    && curl -sL "https://github.com/aquasecurity/tfsec/releases/download/v1.28.11/tfsec-linux-$(dpkg --print-architecture)" \
         -o /tmp/tfsec \
    && chmod +x /tmp/tfsec \
    && /tmp/tfsec --version

# ── Stage 2: Final slim image ─────────────────────────────────
FROM python:3.11-slim AS final

LABEL maintainer="devsecops-agent"
LABEL description="Local AI DevSecOps Agent - Containerized"
LABEL version="1.0.0"

# Create non-root user for security (never run as root)
RUN groupadd -r agent && useradd -r -g agent -m -d /home/agent agent

WORKDIR /app

# Runtime OS dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder stage
COPY --from=builder /install /usr/local

# Copy security tool binaries from builder stage
COPY --from=builder /tmp/terraform_bin/terraform /usr/local/bin/terraform
COPY --from=builder /tmp/tfsec                   /usr/local/bin/tfsec
COPY --from=builder /tmp/trivy                   /usr/local/bin/trivy

# Install checkov (pure Python — pip is more reliable than binary download)
RUN pip install --no-cache-dir checkov

# Copy application source code
COPY agent/   ./agent/
COPY main.py  ./main.py
COPY tests/   ./tests/

# Create persistent volume directories, owned by agent user
RUN mkdir -p /app/outputs /app/logs /app/secrets /app/scan_reports \
    && chown -R agent:agent /app

# Copy entrypoint — supports both root-level and docker/ subdirectory layouts
COPY entrypoint.sh* docker/entrypoint.sh* /tmp/ep_candidates/
RUN if [ -f /tmp/ep_candidates/entrypoint.sh ]; then \
        cp /tmp/ep_candidates/entrypoint.sh /entrypoint.sh; \
    else \
        echo "ERROR: entrypoint.sh not found"; exit 1; \
    fi \
    && chmod +x /entrypoint.sh \
    && rm -rf /tmp/ep_candidates

# Switch to non-root user
USER agent

# Smoke-test that the binaries are all working
RUN terraform version \
    && tfsec --version \
    && trivy --version \
    && python3 -c "import colorama, jinja2; print('Python deps OK')"

# Persistent volumes for outputs and logs
VOLUME ["/app/outputs", "/app/logs", "/app/secrets"]

# Force colour output and buffering off for interactive terminal
ENV PYTHONUNBUFFERED=1
ENV TERM=xterm-256color
ENV COLORAMA_FORCE=1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["run"]
