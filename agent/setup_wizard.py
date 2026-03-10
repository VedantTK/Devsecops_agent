"""
setup_wizard.py
Interactive wizard: cloud selection → credentials → IaC tool selection.
All secrets captured in-memory only; never written to disk in plaintext.
"""
import os
import sys
from dataclasses import dataclass, field
from typing import Optional
from agent.terminal_ui import (
    section, step, info, ok, warn, error, working,
    choice_menu, text_input, secret_input, confirm,
    summary_box, key_value, code_block,
    Fore, Back, Style, BRT, RST, DIM
)

# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class AWSCredentials:
    access_key_id: str = ""
    secret_access_key: str = ""
    region: str = "ap-south-1"
    session_token: Optional[str] = None   # for assumed roles
    profile: Optional[str] = None

@dataclass
class GCPCredentials:
    project_id: str = ""
    service_account_key_path: str = ""
    region: str = "asia-south1"

@dataclass
class AzureCredentials:
    subscription_id: str = ""
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    region: str = "centralindia"

@dataclass
class AgentSession:
    cloud: str = ""                         # aws | gcp | azure
    iac_tool: str = ""                      # terraform | pulumi
    credentials: object = None
    region: str = ""
    env_vars: dict = field(default_factory=dict)   # injected into subprocess
    compliance_targets: list = field(default_factory=list)

# ─── Region maps ─────────────────────────────────────────────────────────────

AWS_REGIONS = [
    ("ap-south-1",      "Mumbai (India)",         "🇮🇳"),
    ("us-east-1",       "N. Virginia (USA)",       "🇺🇸"),
    ("us-west-2",       "Oregon (USA)",            "🇺🇸"),
    ("eu-west-1",       "Ireland (Europe)",        "🇮🇪"),
    ("ap-southeast-1",  "Singapore",               "🇸🇬"),
    ("ap-northeast-1",  "Tokyo (Japan)",           "🇯🇵"),
    ("eu-central-1",    "Frankfurt (Germany)",     "🇩🇪"),
    ("sa-east-1",       "São Paulo (Brazil)",      "🇧🇷"),
    ("ap-east-1",       "Hong Kong",               "🇭🇰"),
    ("me-south-1",      "Bahrain (Middle East)",   "🇧🇭"),
]

GCP_REGIONS = [
    ("asia-south1",       "Mumbai (India)",         "🇮🇳"),
    ("us-central1",       "Iowa (USA)",             "🇺🇸"),
    ("us-east1",          "South Carolina (USA)",   "🇺🇸"),
    ("europe-west1",      "Belgium (Europe)",       "🇧🇪"),
    ("asia-east1",        "Taiwan",                 "🇹🇼"),
    ("asia-northeast1",   "Tokyo (Japan)",          "🇯🇵"),
    ("asia-southeast1",   "Singapore",              "🇸🇬"),
    ("europe-west4",      "Netherlands",            "🇳🇱"),
]

AZURE_REGIONS = [
    ("centralindia",     "Pune / Mumbai (India)",  "🇮🇳"),
    ("eastus",           "Virginia (USA)",         "🇺🇸"),
    ("westus2",          "Washington (USA)",       "🇺🇸"),
    ("westeurope",       "Netherlands",            "🇳🇱"),
    ("southeastasia",    "Singapore",              "🇸🇬"),
    ("japaneast",        "Tokyo (Japan)",          "🇯🇵"),
    ("uksouth",          "London (UK)",            "🇬🇧"),
    ("germanywestcentral","Frankfurt (Germany)",   "🇩🇪"),
]

COMPLIANCE_CHOICES = [
    ("CIS",   "CIS Benchmarks — hardening best practices"),
    ("SOC2",  "SOC 2 Type II — trust service criteria"),
    ("NIST",  "NIST 800-53 — federal security controls"),
    ("HIPAA", "HIPAA — healthcare data protection"),
    ("PCI",   "PCI-DSS — payment card industry"),
]

# ─── Cloud Selection ──────────────────────────────────────────────────────────

def select_cloud() -> str:
    section("CLOUD PROVIDER SELECTION", "☁")
    options = [
        ("AWS",   "Amazon Web Services   — EC2, EKS, S3, RDS, VPC ...", "boto3 SDK"),
        ("GCP",   "Google Cloud Platform — GKE, GCS, Compute, VPC ...", "google-cloud SDK"),
        ("Azure", "Microsoft Azure       — AKS, Blob, VNet, VM  ...", "azure-identity SDK"),
    ]
    idx, selected = choice_menu("Select your cloud provider:", options, icon="☁")
    return selected[0].lower()


# ─── Region Selection ─────────────────────────────────────────────────────────

def select_region(cloud: str) -> str:
    region_map = {"aws": AWS_REGIONS, "gcp": GCP_REGIONS, "azure": AZURE_REGIONS}
    regions = region_map[cloud]

    section("REGION SELECTION", "🌏")
    options = [(f"{flag}  {code}", name, code) for code, name, flag in regions]
    options.append(("✏  Custom", "Enter a custom region code", "custom"))

    idx, selected = choice_menu("Select deployment region:", options, icon="🌏")
    if selected[2] == "custom":
        return text_input("Enter region code", default=regions[0][0])
    return selected[2]


# ─── Credentials Collection ───────────────────────────────────────────────────

def collect_aws_credentials(region: str) -> tuple[AWSCredentials, dict]:
    section("AWS CREDENTIALS", "🔐")
    print(f"  {DIM}Credentials are stored in memory only and injected as env vars.")
    print(f"  They are never written to disk, logs, or sent to any external service.{RST}\n")

    print(f"  {BRT}{Fore.CYAN}Authentication method:{RST}\n")
    auth_options = [
        ("Access Keys",    "IAM user access key + secret (recommended for development)"),
        ("IAM Role / SSO", "Assume role via session token or AWS SSO"),
        ("AWS Profile",    "Use existing ~/.aws/credentials profile"),
    ]
    auth_idx, _ = choice_menu("How do you want to authenticate?", auth_options, icon="🔑")

    creds = AWSCredentials(region=region)

    if auth_idx == 0:
        creds.access_key_id     = text_input("AWS Access Key ID",     secret=True)
        creds.secret_access_key = text_input("AWS Secret Access Key", secret=True)
        if confirm("Do you have a session token (MFA/assumed role)?", default=False):
            creds.session_token = text_input("Session Token", secret=True)

    elif auth_idx == 1:
        creds.access_key_id     = text_input("AWS Access Key ID",     secret=True)
        creds.secret_access_key = text_input("AWS Secret Access Key", secret=True)
        creds.session_token     = text_input("Session Token",         secret=True)

    else:  # profile
        profiles = _detect_aws_profiles()
        if profiles:
            info(f"Detected profiles: {', '.join(profiles)}")
        creds.profile = text_input("Profile name", default="default")
        # When using profile, we read from ~/.aws — no keys entered here
        ok(f"Will use AWS profile: {creds.profile}")

    env_vars = _aws_to_env(creds)
    return creds, env_vars


def collect_gcp_credentials(region: str) -> tuple[GCPCredentials, dict]:
    section("GCP CREDENTIALS", "🔐")
    print(f"  {DIM}Service account key path is stored in memory.")
    print(f"  The key file remains on your disk — only the path is used.{RST}\n")

    creds = GCPCredentials(region=region)
    creds.project_id = text_input("GCP Project ID", default="my-project")

    print(f"\n  {BRT}{Fore.CYAN}Authentication method:{RST}\n")
    auth_options = [
        ("Service Account Key", "JSON key file from GCP Console (recommended)"),
        ("Application Default",  "gcloud auth application-default login"),
        ("Workload Identity",    "For GKE / Cloud Run (no key file needed)"),
    ]
    auth_idx, _ = choice_menu("Authentication method:", auth_options, icon="🔑")

    if auth_idx == 0:
        key_path = text_input("Path to service account JSON key file",
                               default="~/.config/gcloud/service-account.json")
        creds.service_account_key_path = os.path.expanduser(key_path)
        if not os.path.exists(creds.service_account_key_path):
            warn(f"Key file not found at: {creds.service_account_key_path}")
            warn("Will proceed — ensure the file exists before deployment")
    elif auth_idx == 1:
        info("Will use Application Default Credentials (gcloud auth)")
        creds.service_account_key_path = "ADC"
    else:
        info("Will use Workload Identity Federation")
        creds.service_account_key_path = "WORKLOAD_IDENTITY"

    env_vars = _gcp_to_env(creds)
    return creds, env_vars


def collect_azure_credentials(region: str) -> tuple[AzureCredentials, dict]:
    section("AZURE CREDENTIALS", "🔐")
    print(f"  {DIM}Credentials are stored in memory only — never persisted to disk.{RST}\n")

    creds = AzureCredentials(region=region)

    print(f"  {BRT}{Fore.CYAN}Authentication method:{RST}\n")
    auth_options = [
        ("Service Principal", "Client ID + Client Secret (recommended for automation)"),
        ("Azure CLI",          "az login — uses your existing CLI session"),
        ("Managed Identity",   "For Azure VMs / App Service (no credentials needed)"),
    ]
    auth_idx, _ = choice_menu("Authentication method:", auth_options, icon="🔑")

    creds.subscription_id = text_input("Subscription ID", secret=True)

    if auth_idx == 0:
        creds.tenant_id     = text_input("Tenant ID",     secret=True)
        creds.client_id     = text_input("Client ID",     secret=True)
        creds.client_secret = text_input("Client Secret", secret=True)
    elif auth_idx == 1:
        info("Will use Azure CLI credentials — ensure 'az login' is done")
    else:
        info("Will use Managed Identity — ensure MSI is enabled on this VM")

    env_vars = _azure_to_env(creds)
    return creds, env_vars


# ─── IaC Tool Selection ───────────────────────────────────────────────────────

def select_iac_tool() -> str:
    section("INFRASTRUCTURE-AS-CODE TOOL", "⚙")
    options = [
        ("Terraform", "HashiCorp Terraform — HCL language, widest provider support", ".tf files"),
        ("Pulumi",    "Pulumi — use Python/TypeScript/Go instead of HCL",            ".py files"),
    ]
    idx, selected = choice_menu("Select your IaC tool:", options, icon="⚙")

    tool = selected[0].lower()

    # Check if tool is installed
    installed = _check_tool_installed(tool)
    if installed:
        ok(f"{selected[0]} is installed ✓")
    else:
        warn(f"{selected[0]} not found in PATH — generated code will still be written")
        warn(f"Install {selected[0]} before running deployment")
        _print_install_hint(tool)

    return tool


# ─── Compliance Selection ─────────────────────────────────────────────────────

def select_compliance() -> list:
    section("COMPLIANCE FRAMEWORKS", "📋")
    info("Select the compliance frameworks to enforce (you can skip this).")
    print()

    if not confirm("Enable compliance scanning?", default=True):
        info("Skipping compliance framework selection")
        return []

    selected = []
    for label, desc in COMPLIANCE_CHOICES:
        if confirm(f"  Enable {label} ({desc})?", default=(label in ("CIS",))):
            selected.append(label.lower())

    if selected:
        ok(f"Compliance targets: {', '.join(t.upper() for t in selected)}")
    return selected


# ─── Session Summary ──────────────────────────────────────────────────────────

def print_session_summary(session: AgentSession):
    section("SESSION CONFIGURATION SUMMARY", "📊")

    region_display = session.region
    items = [
        ("Cloud Provider",   session.cloud.upper()),
        ("Region",           region_display),
        ("IaC Tool",         session.iac_tool.capitalize()),
        ("Compliance",       ", ".join(t.upper() for t in session.compliance_targets) or "None"),
        ("Credentials",      "In-memory only  (never written to disk)"),
        ("LLM Backend",      "Ollama (local)  — no data sent externally"),
    ]
    summary_box("Agent Session", items)

    print(f"  {DIM}Your credentials are held in memory for this session only.")
    print(f"  They will be injected as environment variables when running {session.iac_tool}.")
    print(f"  No credentials will appear in generated code, logs, or state files.{RST}\n")


# ─── Full Wizard ──────────────────────────────────────────────────────────────

def run_setup_wizard() -> AgentSession:
    """
    Full interactive setup wizard.
    Returns a populated AgentSession ready for the prompt loop.
    """
    session = AgentSession()

    # 1. Cloud
    step(1, "SELECT YOUR CLOUD PROVIDER")
    session.cloud = select_cloud()

    # 2. Region
    step(2, "SELECT YOUR DEPLOYMENT REGION")
    session.region = select_region(session.cloud)

    # 3. Credentials
    step(3, "ENTER YOUR CLOUD CREDENTIALS")
    if session.cloud == "aws":
        creds, env_vars = collect_aws_credentials(session.region)
    elif session.cloud == "gcp":
        creds, env_vars = collect_gcp_credentials(session.region)
    else:
        creds, env_vars = collect_azure_credentials(session.region)

    session.credentials = creds
    session.env_vars = env_vars

    # 4. IaC tool
    step(4, "SELECT INFRASTRUCTURE-AS-CODE TOOL")
    session.iac_tool = select_iac_tool()

    # 5. Compliance
    step(5, "COMPLIANCE FRAMEWORKS (OPTIONAL)")
    session.compliance_targets = select_compliance()

    # 6. Summary + confirm
    print_session_summary(session)

    if not confirm("Everything looks good — proceed to the agent prompt?", default=True):
        warn("Restarting wizard...")
        return run_setup_wizard()

    return session


# ─── Private helpers ──────────────────────────────────────────────────────────

def _aws_to_env(creds: AWSCredentials) -> dict:
    env = {"AWS_DEFAULT_REGION": creds.region}
    if creds.profile:
        env["AWS_PROFILE"] = creds.profile
    else:
        if creds.access_key_id:
            env["AWS_ACCESS_KEY_ID"] = creds.access_key_id
        if creds.secret_access_key:
            env["AWS_SECRET_ACCESS_KEY"] = creds.secret_access_key
        if creds.session_token:
            env["AWS_SESSION_TOKEN"] = creds.session_token
    return env

def _gcp_to_env(creds: GCPCredentials) -> dict:
    env = {"GCP_PROJECT_ID": creds.project_id,
           "CLOUDSDK_COMPUTE_REGION": creds.region}
    if creds.service_account_key_path not in ("ADC", "WORKLOAD_IDENTITY", ""):
        env["GOOGLE_APPLICATION_CREDENTIALS"] = creds.service_account_key_path
    return env

def _azure_to_env(creds: AzureCredentials) -> dict:
    env = {}
    if creds.subscription_id: env["AZURE_SUBSCRIPTION_ID"] = creds.subscription_id
    if creds.tenant_id:        env["AZURE_TENANT_ID"]       = creds.tenant_id
    if creds.client_id:        env["AZURE_CLIENT_ID"]       = creds.client_id
    if creds.client_secret:    env["AZURE_CLIENT_SECRET"]   = creds.client_secret
    env["AZURE_LOCATION"] = creds.region
    return env

def _detect_aws_profiles() -> list:
    creds_file = os.path.expanduser("~/.aws/credentials")
    profiles = []
    if os.path.exists(creds_file):
        with open(creds_file) as f:
            for line in f:
                line = line.strip()
                if line.startswith("[") and line.endswith("]"):
                    profiles.append(line[1:-1])
    return profiles

def _check_tool_installed(tool: str) -> bool:
    import shutil
    return shutil.which(tool) is not None

def _print_install_hint(tool: str):
    hints = {
        "terraform": [
            "# Install Terraform",
            "wget https://releases.hashicorp.com/terraform/1.7.0/terraform_1.7.0_linux_amd64.zip",
            "unzip terraform_*.zip && sudo mv terraform /usr/local/bin/",
        ],
        "pulumi": [
            "# Install Pulumi",
            "curl -fsSL https://get.pulumi.com | sh",
        ]
    }
    from agent.terminal_ui import code_block
    code_block(f"Install {tool.capitalize()}", hints.get(tool, []))
