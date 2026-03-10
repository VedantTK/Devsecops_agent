# 🛡 Local AI DevSecOps Agent

A fully local, privacy-first terminal agent that generates and deploys secure
cloud infrastructure from natural language prompts.

**All credentials stay on your machine — nothing sent externally.**

---

## Quick Start

```bash
# 1. Install dependencies (only 2 packages needed)
pip install colorama jinja2

# 2. Run the agent
python main.py
```

## What happens when you run it

```
Step 1 → Select cloud provider     (AWS / GCP / Azure)
Step 2 → Select region             (Mumbai, US, EU, etc.)
Step 3 → Enter credentials         (masked input, memory only)
Step 4 → Select IaC tool           (Terraform / Pulumi)
Step 5 → Select compliance         (CIS / SOC2 / NIST — optional)

Then → type prompts like:
  "make secure infra with 1 private instance in mumbai region"
  "create production vpc with 2 private subnets"
  "deploy 3 t3.small private instances with encrypted storage"
```

## Folder Structure

```
devsecops_agent/
├── main.py                   ← RUN THIS
├── requirements.txt
├── agent/
│   ├── terminal_ui.py        ← Colors, banners, menus
│   ├── setup_wizard.py       ← Cloud/creds/IaC wizard
│   ├── iac_generator.py      ← Terraform/Pulumi generator
│   ├── security_scanner.py   ← tfsec, checkov, trivy, guardrails
│   └── agent_loop.py         ← Main prompt loop
├── outputs/                  ← Generated IaC files go here
├── logs/                     ← Audit log (audit.jsonl)
├── secrets/                  ← NEVER commit (gitignored)
├── scan_reports/             ← Scanner output
├── templates/                ← Jinja2 IaC templates
└── policies/                 ← OPA/Rego security policies
```

## Install Security Scanners (optional but recommended)

```bash
# checkov
pip install checkov

# tfsec
curl -sL https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh | bash

# trivy
sudo apt-get install trivy   # or brew install trivy

# terrascan
curl -L "https://github.com/tenable/terrascan/releases/latest/download/terrascan_Linux_x86_64.tar.gz" | tar -xz
sudo mv terrascan /usr/local/bin/
```

If none are installed, the agent uses its built-in guardrail scanner.

## Audit Existing Terraform

```bash
python main.py audit ./path/to/terraform/
```

## Commands inside the agent

| Command | Description |
|---------|-------------|
| `<any prompt>` | Generate secure infrastructure |
| `audit <path>` | Audit existing IaC code |
| `show config` | Show current session config |
| `show last` | Show last generated output |
| `help` | Show all commands |
| `exit` | Exit the agent |

## Security guarantees

- Credentials entered via `getpass` (masked, memory only)
- Credentials injected as subprocess env vars at deploy time
- Hardcoded secrets blocked by guardrail regex scanner
- Generated code scanned before any deployment
- Audit log written to `logs/audit.jsonl`
