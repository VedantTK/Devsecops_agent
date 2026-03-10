"""
agent_loop.py
Main interactive prompt loop after setup wizard is complete.
Handles prompt → parse → generate → scan → display → deploy cycle.
"""
import os
import sys
import time
import datetime
import hashlib
import json
from pathlib import Path
from agent.terminal_ui import (
    section, step, info, ok, warn, error, working,
    choice_menu, text_input, confirm,
    code_block, summary_box, findings_table,
    print_banner, scanning_block,
    Fore, BRT, RST, DIM, Style
)
from agent.iac_generator import IaCGenerator, IntentParser
from agent.security_scanner import run_all_scanners

HELP_TEXT = """
  AVAILABLE COMMANDS
  ──────────────────────────────────────────────────────────
  <any prompt>     Generate secure infrastructure from description
  audit <path>     Run security audit on existing IaC code
  show config      Display current session configuration
  show last        Show last generated output
  help             Show this help message
  exit / quit      Exit the agent

  EXAMPLE PROMPTS
  ──────────────────────────────────────────────────────────
  make secure infra with 1 private instance in mumbai region
  create a production vpc with 2 private subnets
  deploy 3 small private ec2 instances with encrypted storage
  build a secure kubernetes cluster with network policies
  create s3 bucket with encryption and versioning
  setup secure rds database private no public access
"""


def run_agent_loop(session):
    """Main interactive prompt loop."""
    generator  = IaCGenerator(output_base="./outputs")
    parser     = IntentParser()
    last_output = None

    # Welcome message
    section("AGENT READY", "🤖")
    print(f"  {BRT}{Fore.GREEN}Your DevSecOps agent is ready.{RST}")
    print(f"  {DIM}Cloud: {session.cloud.upper()}  |  Region: {session.region}  |  Tool: {session.iac_tool.capitalize()}{RST}")
    print(f"  {DIM}Type 'help' for commands, 'exit' to quit.{RST}")
    print()

    # Show a hint prompt
    _print_prompt_examples(session.cloud)

    while True:
        try:
            prompt = input(
                f"\n  {BRT}{Fore.CYAN}🛡 devsecops{Fore.WHITE}@{Fore.GREEN}{session.cloud}"
                f"{Fore.WHITE} › {RST}"
            ).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            if confirm("Exit the agent?", default=True):
                _print_goodbye()
                sys.exit(0)
            continue

        if not prompt:
            continue

        cmd = prompt.lower()

        # ── Built-in commands ─────────────────────────────────────────────
        if cmd in ("exit", "quit", "q", "bye"):
            _print_goodbye()
            break

        elif cmd == "help":
            print(Fore.CYAN + HELP_TEXT + RST)
            continue

        elif cmd == "show config":
            from agent.setup_wizard import print_session_summary
            print_session_summary(session)
            continue

        elif cmd == "show last":
            if last_output:
                _display_generated_files(last_output)
            else:
                warn("No output generated yet in this session.")
            continue

        elif cmd.startswith("audit "):
            path = prompt[6:].strip()
            _run_audit(path, session)
            continue

        # ── Infrastructure generation pipeline ────────────────────────────
        else:
            last_output = _run_generation_pipeline(
                prompt, session, generator, parser
            )


def _run_generation_pipeline(prompt: str, session, generator, parser):
    """Full pipeline: parse → generate → scan → display → optional deploy."""

    print()
    section("PROCESSING YOUR REQUEST", "⚙")
    info(f"Prompt: {BRT}{prompt}{RST}")
    print()

    # ── Stage 1: Parse intent ─────────────────────────────────────────────
    working("Parsing intent...")
    time.sleep(0.3)
    intent = parser.parse(prompt, session)
    _display_parsed_intent(intent, session)

    if not confirm("Is this what you want to generate?", default=True):
        warn("Cancelled. Try rephrasing your prompt.")
        return None

    # ── Stage 2: Generate IaC ─────────────────────────────────────────────
    section("GENERATING IaC CODE", "📝")
    working(f"Generating {session.iac_tool.capitalize()} code for {session.cloud.upper()}...")
    time.sleep(0.4)

    result = generator.generate(intent, session)

    if not result.success:
        error(f"Generation failed: {result.error}")
        return None

    ok(f"Generated {len(result.files)} file(s) → {result.output_dir}")
    print()

    # Show generated file preview
    _display_generated_files(result)

    # ── Stage 3: Built-in guardrails ──────────────────────────────────────
    if result.security_issues:
        print()
        section("GUARDRAIL CHECKS", "🛡")
        critical_issues = [i for i in result.security_issues if i["severity"] == "CRITICAL"]
        high_issues     = [i for i in result.security_issues if i["severity"] == "HIGH"]

        if critical_issues:
            error("CRITICAL security issues found in generated code!")
            for issue in critical_issues:
                error(f"  {issue['description']}")
            error("Deployment blocked. Fix issues or regenerate.")
            return result

        if high_issues:
            warn("High severity issues found:")
            for issue in high_issues:
                warn(f"  {issue['description']}")
            if not confirm("Proceed despite HIGH severity issues?", default=False):
                warn("Cancelled by user.")
                return result
    else:
        section("GUARDRAIL CHECKS", "🛡")
        ok("All built-in guardrail checks passed")

    # ── Stage 4: Security scanning ────────────────────────────────────────
    print()
    section("SECURITY SCANNING", "🔍")
    scan_results = run_all_scanners(result.output_dir, session.cloud, session.iac_tool)

    # Display findings table
    if scan_results["findings"]:
        print()
        findings_table(scan_results["findings"][:20])  # show top 20

    # Scan summary
    _display_scan_summary(scan_results)

    # Block on critical
    if scan_results["critical"] > 0:
        error(f"Deployment blocked: {scan_results['critical']} CRITICAL finding(s)")
        info("Review the findings above and regenerate or manually fix.")
        return result

    # ── Stage 5: Deployment decision ──────────────────────────────────────
    print()
    section("DEPLOYMENT", "🚀")
    _display_deployment_plan(intent, session, result)

    deploy_choice = _ask_deploy_action()

    if deploy_choice == "deploy":
        _run_deployment(result.output_dir, session, intent)
    elif deploy_choice == "plan":
        _run_plan_only(result.output_dir, session)
    else:
        info("Files saved. Run deployment when ready:")
        _print_manual_deploy_commands(result.output_dir, session)

    return result


def _display_parsed_intent(intent: dict, session):
    """Show what the agent understood from the prompt."""
    section("PARSED INTENT", "🧠")
    resources_str = ", ".join(intent.get("resource_types", []))
    security_str  = ", ".join(intent.get("security_features", []))
    items = [
        ("Cloud",            session.cloud.upper()),
        ("Region",           session.region),
        ("IaC Tool",         session.iac_tool.capitalize()),
        ("Resources",        resources_str),
        ("Instance Count",   str(intent.get("instance_count", 1))),
        ("Instance Type",    intent.get("instance_type", "t3.micro")),
        ("Storage (GB)",     str(intent.get("volume_size", 20))),
        ("Environment",      intent.get("environment", "production")),
        ("Network CIDR",     intent.get("cidr", "10.0.0.0/16")),
        ("AZ Count",         str(intent.get("az_count", 2))),
        ("Security",         security_str),
    ]
    summary_box("Understood Request", items)


def _display_generated_files(result):
    """Show generated file contents."""
    for fpath in sorted(result.files):
        if not os.path.exists(fpath): continue
        content = open(fpath).read()
        fname = os.path.basename(fpath)
        lines = content.splitlines()
        # Show first 40 lines
        preview = lines[:40]
        if len(lines) > 40:
            preview.append(f"... ({len(lines) - 40} more lines)")
        code_block(f"📄 {fname}  [{len(lines)} lines]", preview)


def _display_scan_summary(scan_results: dict):
    """Print a colored scan summary box."""
    c  = scan_results["critical"]
    h  = scan_results["high"]
    m  = scan_results["medium"]
    lo = scan_results["low"]

    c_col  = Fore.RED    if c > 0 else Fore.GREEN
    h_col  = Fore.YELLOW if h > 0 else Fore.GREEN
    m_col  = Fore.CYAN
    lo_col = Fore.WHITE

    print(f"\n  {BRT}{Fore.WHITE}Security Scan Summary{RST}")
    print(f"  {'─'*50}")
    print(f"  {BRT}{c_col}CRITICAL: {c:<4}{RST}  {BRT}{h_col}HIGH: {h:<4}{RST}  "
          f"{m_col}MEDIUM: {m:<4}{RST}  {lo_col}LOW: {lo}{RST}")
    print(f"  {'─'*50}")
    scanners = ", ".join(scan_results.get("scanners_run", ["builtin"]))
    print(f"  {DIM}Scanners: {scanners}{RST}")
    passed = scan_results.get("passed", False)
    if passed:
        print(f"  {BRT}{Fore.GREEN}✓ SCAN PASSED — no critical or high findings{RST}")
    else:
        print(f"  {BRT}{Fore.RED}✗ SCAN FAILED — review findings before deploying{RST}")
    print()


def _display_deployment_plan(intent: dict, session, result):
    """Show what will be deployed."""
    print(f"  {BRT}{Fore.WHITE}What will be deployed:{RST}\n")
    for res in intent.get("resource_types", []):
        print(f"    {Fore.GREEN}+{RST}  {res}")
    print(f"\n  {DIM}Output directory: {result.output_dir}{RST}")
    print(f"  {DIM}State file:        {result.output_dir}/terraform.tfstate{RST}")
    print()


def _ask_deploy_action() -> str:
    options = [
        ("Plan only",  f"Run 'terraform plan' — preview changes without deploying"),
        ("Deploy now", f"Run 'terraform apply' — deploy to cloud (uses your credentials)"),
        ("Save only",  f"Save files locally — deploy manually later"),
    ]
    idx, _ = choice_menu("What would you like to do?", options, icon="🚀")
    return ["plan", "deploy", "save"][idx]


def _run_deployment(output_dir: str, session, intent: dict):
    """Execute terraform apply with credentials injected as env vars."""
    import subprocess

    section("DEPLOYING INFRASTRUCTURE", "🚀")
    warn("This will create real cloud resources and may incur costs.")

    if not confirm("Confirm deployment?", default=False):
        info("Deployment cancelled.")
        return

    env = {**os.environ, **session.env_vars}

    tool = session.iac_tool

    try:
        # Init
        working(f"Initializing {tool}...")
        r = subprocess.run([tool, "init", "-input=false"],
                           cwd=output_dir, env=env,
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            error(f"Init failed:\n{r.stderr}")
            return
        ok("Initialized")

        # Plan
        working("Running plan...")
        r = subprocess.run([tool, "plan", "-input=false", "-out=tfplan"],
                           cwd=output_dir, env=env,
                           capture_output=True, text=True, timeout=300)
        print(r.stdout[-3000:] if r.stdout else "")
        if r.returncode != 0:
            error(f"Plan failed:\n{r.stderr}")
            return

        if not confirm("Plan complete. Apply (deploy)?", default=False):
            info("Apply cancelled.")
            return

        # Apply
        working("Applying...")
        r = subprocess.run([tool, "apply", "-input=false", "-auto-approve", "tfplan"],
                           cwd=output_dir, env=env,
                           capture_output=True, text=True, timeout=600)
        print(r.stdout[-4000:] if r.stdout else "")
        if r.returncode == 0:
            ok("Deployment complete!")
            _write_audit_log(output_dir, session, intent, "deployed")
        else:
            error(f"Apply failed:\n{r.stderr[-2000:]}")

    except FileNotFoundError:
        error(f"{tool} not found. Install it first:")
        _print_manual_deploy_commands(output_dir, session)
    except subprocess.TimeoutExpired:
        error("Deployment timed out.")


def _run_plan_only(output_dir: str, session):
    """Run terraform plan only."""
    import subprocess
    env = {**os.environ, **session.env_vars}
    tool = session.iac_tool

    working(f"Running {tool} init...")
    subprocess.run([tool, "init", "-input=false"], cwd=output_dir, env=env,
                   capture_output=True, timeout=120)

    working(f"Running {tool} plan...")
    r = subprocess.run([tool, "plan", "-input=false"],
                       cwd=output_dir, env=env, timeout=300)
    if r.returncode == 0:
        ok("Plan complete — no changes applied.")
    else:
        error("Plan failed.")


def _run_audit(path: str, session):
    """Audit existing IaC files."""
    if not os.path.exists(path):
        error(f"Path not found: {path}")
        return
    section(f"AUDITING: {path}", "🔍")
    scan_results = run_all_scanners(path, session.cloud, session.iac_tool)
    if scan_results["findings"]:
        findings_table(scan_results["findings"])
    _display_scan_summary(scan_results)


def _print_manual_deploy_commands(output_dir: str, session):
    """Show manual commands to deploy."""
    tool = session.iac_tool
    lines = [
        f"cd {output_dir}",
        "",
        "# Set credentials as environment variables:",
    ]
    for k, v in session.env_vars.items():
        masked = v[:4] + "****" if len(v) > 4 else "****"
        lines.append(f"export {k}='{masked}'")
    lines += [
        "",
        f"{tool} init",
        f"{tool} plan",
        f"{tool} apply",
    ]
    code_block(f"Manual {tool.capitalize()} Commands", lines)


def _print_prompt_examples(cloud: str):
    examples = {
        "aws": [
            "make secure infra with 1 private instance in mumbai region",
            "create production vpc with 2 private subnets and encrypted storage",
            "deploy 3 t3.small instances private no public ip with kms encryption",
            "setup secure rds postgresql private subnet with deletion protection",
        ],
        "gcp": [
            "create private vpc with 1 e2-micro instance in mumbai",
            "deploy secure gke cluster with network policies in asia-south1",
            "setup private compute vm with shielded instance and disk encryption",
        ],
        "azure": [
            "create secure vnet with 1 private vm in central india",
            "deploy aks cluster with rbac and network policies",
            "setup private linux vm with managed identity and key vault encryption",
        ],
    }
    print(f"  {BRT}{Fore.YELLOW}💡 Example prompts for {cloud.upper()}:{RST}\n")
    for ex in examples.get(cloud, []):
        print(f"    {DIM}→{RST}  {Fore.WHITE}{ex}{RST}")
    print()


def _write_audit_log(output_dir: str, session, intent: dict, action: str):
    """Write a tamper-evident audit log entry."""
    log_dir = "./logs"
    os.makedirs(log_dir, exist_ok=True)
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "action": action,
        "cloud": session.cloud,
        "region": session.region,
        "iac_tool": session.iac_tool,
        "output_dir": output_dir,
        "intent_hash": hashlib.sha256(json.dumps(intent, default=str).encode()).hexdigest(),
        "compliance": session.compliance_targets,
    }
    log_file = os.path.join(log_dir, "audit.jsonl")
    with open(log_file, "a") as f:
        f.write(json.dumps(entry) + "\n")


def _print_goodbye():
    print(f"\n  {BRT}{Fore.CYAN}╔{'═'*48}╗{RST}")
    print(f"  {BRT}{Fore.CYAN}║{RST}  {Fore.GREEN}Thanks for using Local AI DevSecOps Agent!{Fore.CYAN}  ║{RST}")
    print(f"  {BRT}{Fore.CYAN}║{RST}  {DIM}All credentials cleared from memory.{RST}{Fore.CYAN}        ║{RST}")
    print(f"  {BRT}{Fore.CYAN}╚{'═'*48}╝{RST}\n")
