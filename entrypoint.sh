#!/bin/bash
# =============================================================
# entrypoint.sh — DevSecOps Agent Container Entrypoint
# Handles: run | audit <path> | test | shell | version
# =============================================================
set -e

APP_DIR="/app"
cd "$APP_DIR"

# ── Colour helpers ──────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "  ${CYAN}ℹ${RESET}  $*"; }
ok()      { echo -e "  ${GREEN}✓${RESET}  $*"; }
warn()    { echo -e "  ${YELLOW}⚠${RESET}  $*"; }
err()     { echo -e "  ${RED}✗${RESET}  $*"; }
header()  { echo -e "\n${BOLD}${CYAN}  ══ $* ══${RESET}\n"; }

# ── Startup checks ──────────────────────────────────────────
startup_checks() {
    header "Container Startup Checks"

    # Python
    PYTHON_VER=$(python3 --version 2>&1)
    ok "Python: $PYTHON_VER"

    # Terraform
    if command -v terraform &>/dev/null; then
        TF_VER=$(terraform version -json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['terraform_version'])" 2>/dev/null || terraform version | head -1)
        ok "Terraform: $TF_VER"
    else
        warn "Terraform: not found"
    fi

    # tfsec
    if command -v tfsec &>/dev/null; then
        TFSEC_VER=$(tfsec --version 2>&1 | head -1)
        ok "tfsec: $TFSEC_VER"
    else
        warn "tfsec: not found"
    fi

    # trivy
    if command -v trivy &>/dev/null; then
        TRIVY_VER=$(trivy --version 2>&1 | head -1)
        ok "trivy: $TRIVY_VER"
    else
        warn "trivy: not found"
    fi

    # checkov
    if command -v checkov &>/dev/null; then
        CHECKOV_VER=$(checkov --version 2>&1 | head -1)
        ok "checkov: $CHECKOV_VER"
    else
        warn "checkov: not found"
    fi

    # Output dirs
    for dir in outputs logs secrets scan_reports; do
        if [ -d "/app/$dir" ]; then
            ok "Mount point /app/$dir exists"
        else
            warn "Mount point /app/$dir missing — creating"
            mkdir -p "/app/$dir"
        fi
    done

    echo ""
}

# ── Cloud credentials check ─────────────────────────────────
check_credentials() {
    header "Credential Environment Check"
    local found=0

    # AWS
    if [ -n "$AWS_ACCESS_KEY_ID" ] && [ -n "$AWS_SECRET_ACCESS_KEY" ]; then
        MASKED="${AWS_ACCESS_KEY_ID:0:4}****"
        ok "AWS credentials detected (key: $MASKED)"
        found=1
    elif [ -n "$AWS_PROFILE" ]; then
        ok "AWS profile set: $AWS_PROFILE"
        found=1
    fi

    # GCP
    if [ -n "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
        ok "GCP credentials file: $GOOGLE_APPLICATION_CREDENTIALS"
        found=1
    fi

    # Azure
    if [ -n "$AZURE_CLIENT_ID" ] && [ -n "$AZURE_CLIENT_SECRET" ]; then
        ok "Azure service principal credentials detected"
        found=1
    fi

    if [ "$found" -eq 0 ]; then
        info "No cloud credentials pre-loaded via environment."
        info "The interactive wizard will ask for them."
    fi

    echo ""
}

# ── Mode dispatcher ─────────────────────────────────────────
MODE="${1:-run}"

case "$MODE" in

    # ── Interactive agent ─────────────────────────────────
    run)
        startup_checks
        check_credentials
        info "Starting interactive DevSecOps Agent..."
        info "Outputs will be saved to /app/outputs (mounted volume)"
        echo ""
        exec python3 -u main.py
        ;;

    # ── Audit-only mode ───────────────────────────────────
    audit)
        AUDIT_PATH="${2:-/app/outputs}"
        startup_checks
        info "Running audit on: $AUDIT_PATH"
        exec python3 -u main.py audit "$AUDIT_PATH"
        ;;

    # ── Run tests ─────────────────────────────────────────
    test)
        header "Running Smoke Tests"
        exec python3 -u tests/test_agent.py
        ;;

    # ── Print version info ────────────────────────────────
    version)
        echo ""
        echo -e "${BOLD}${CYAN}DevSecOps Agent — Tool Versions${RESET}"
        echo "─────────────────────────────────"
        python3 --version
        terraform version 2>/dev/null | head -1 || echo "terraform: not found"
        tfsec --version 2>/dev/null | head -1 || echo "tfsec: not found"
        trivy --version 2>/dev/null | head -1 || echo "trivy: not found"
        checkov --version 2>/dev/null || echo "checkov: not found"
        echo ""
        ;;

    # ── Bash shell (debugging) ────────────────────────────
    shell | bash)
        warn "Starting shell inside container (debug mode)..."
        exec /bin/bash
        ;;

    # ── Direct python command ─────────────────────────────
    python*)
        exec "$@"
        ;;

    # ── Unknown ───────────────────────────────────────────
    *)
        err "Unknown command: $MODE"
        echo ""
        echo "Usage:"
        echo "  docker run -it devsecops-agent run           # interactive agent"
        echo "  docker run -it devsecops-agent audit <path>  # audit IaC files"
        echo "  docker run    devsecops-agent test           # run smoke tests"
        echo "  docker run    devsecops-agent version        # print versions"
        echo "  docker run -it devsecops-agent shell         # bash shell"
        exit 1
        ;;
esac
