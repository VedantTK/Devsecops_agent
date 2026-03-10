"""
agent_loop.py
Main interactive prompt loop after setup wizard is complete.
Handles prompt → parse → generate → scan → display → deploy → destroy cycle.
"""
import os
import sys
import time
import shutil
import datetime
import hashlib
import json
import subprocess
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
  <any prompt>        Generate & deploy secure infrastructure
  destroy <path>      Destroy infrastructure from an output dir
  destroy last        Destroy the last deployed infrastructure
  list                List all output directories with state
  audit <path>        Run security audit on existing IaC code
  show config         Display current session configuration
  show last           Show last generated output files
  help                Show this help message
  exit / quit         Exit the agent

  DESTROY EXAMPLES
  ──────────────────────────────────────────────────────────
  destroy last
  destroy ./outputs/aws_c657fee3
  destroy ./outputs/aws_abc12345

  GENERATE EXAMPLES
  ──────────────────────────────────────────────────────────
  make secure infra with 1 private instance in mumbai region
  create a production vpc with 2 private subnets
  deploy 3 small private ec2 instances with encrypted storage
"""

INSTALL_HINTS = {
    "terraform": [
        "# Option 1 - Official installer (Linux/macOS)",
        "wget https://releases.hashicorp.com/terraform/1.7.5/terraform_1.7.5_linux_amd64.zip",
        "unzip terraform_1.7.5_linux_amd64.zip",
        "sudo mv terraform /usr/local/bin/",
        "terraform -version",
        "",
        "# Option 2 - Homebrew (macOS)",
        "brew tap hashicorp/tap && brew install hashicorp/tap/terraform",
        "",
        "# Option 3 - tfenv version manager",
        "git clone https://github.com/tfutils/tfenv.git ~/.tfenv",
        "ln -s ~/.tfenv/bin/* /usr/local/bin/",
        "tfenv install latest && tfenv use latest",
    ],
    "pulumi": [
        "# Linux / macOS",
        "curl -fsSL https://get.pulumi.com | sh",
        "",
        "# Homebrew (macOS)",
        "brew install pulumi/tap/pulumi",
        "",
        "pulumi version",
    ],
}


# ─── Tool availability check ──────────────────────────────────────────────────

def _is_tool_installed(tool):
    return shutil.which(tool) is not None


def _check_tool_or_show_install(tool, output_dir, session):
    if _is_tool_installed(tool):
        return True
    print()
    error(f"'{tool}' is not installed or not found in your PATH.")
    print()
    print(f"  {BRT}{Fore.YELLOW}Your infrastructure code has been generated and saved successfully.{RST}")
    print(f"  {Fore.WHITE}Install {tool.capitalize()} then run these commands:{RST}")
    print()
    hints = INSTALL_HINTS.get(tool, [f"Visit https://{tool}.io for install instructions"])
    code_block(f"Step 1 - Install {tool.capitalize()}", hints)
    _print_manual_deploy_commands(output_dir, session)
    return False


# ─── Output directory tracker ─────────────────────────────────────────────────

def _list_output_dirs(base="./outputs"):
    """Return all output dirs that contain a .tf file and state file."""
    dirs = []
    if not os.path.exists(base):
        return dirs
    for entry in sorted(Path(base).iterdir()):
        if not entry.is_dir():
            continue
        has_tf    = any(entry.glob("*.tf")) or any(entry.glob("*.py"))
        has_state = (entry / "terraform.tfstate").exists()
        dirs.append({
            "path":      str(entry),
            "name":      entry.name,
            "has_tf":    has_tf,
            "has_state": has_state,
            "deployed":  has_state and _state_has_resources(entry / "terraform.tfstate"),
        })
    return dirs


def _state_has_resources(state_path):
    """Check if a terraform.tfstate has any managed resources."""
    try:
        data = json.loads(open(state_path).read())
        resources = data.get("resources", [])
        return len(resources) > 0
    except Exception:
        return False


def _get_resource_count(state_path):
    """Count resources in a state file."""
    try:
        data = json.loads(open(state_path).read())
        return len(data.get("resources", []))
    except Exception:
        return 0


# ─── Main agent loop ──────────────────────────────────────────────────────────

def run_agent_loop(session):
    generator   = IaCGenerator(output_base="./outputs")
    parser      = IntentParser()
    last_output = None

    tool = session.iac_tool
    if not _is_tool_installed(tool):
        print()
        warn(f"'{tool}' is not installed - code generation works but Plan/Deploy/Destroy will be skipped.")
        info(f"Install {tool.capitalize()} when ready.")
        print()

    section("AGENT READY", "🤖")
    installed_str = (f"{Fore.GREEN}installed{RST}" if _is_tool_installed(tool)
                     else f"{Fore.RED}not installed{RST}")
    print(f"  {BRT}{Fore.GREEN}Your DevSecOps agent is ready.{RST}")
    print(f"  {DIM}Cloud: {session.cloud.upper()}  |  Region: {session.region}  |  "
          f"Tool: {session.iac_tool.capitalize()} ({installed_str}{DIM}){RST}")
    print(f"  {DIM}Type 'help' for commands, 'exit' to quit.{RST}")
    print()

    _print_prompt_examples(session.cloud)

    while True:
        try:
            prompt = input(
                f"\n  {BRT}{Fore.CYAN}devsecops{Fore.WHITE}@{Fore.GREEN}{session.cloud}"
                f"{Fore.WHITE} > {RST}"
            ).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            if confirm("Exit the agent?", default=True):
                _print_goodbye()
                sys.exit(0)
            continue

        if not prompt:
            continue

        cmd = prompt.lower().strip()

        # ── Built-in commands ──────────────────────────────────────────────
        if cmd in ("exit", "quit", "q", "bye"):
            _print_goodbye()
            break

        elif cmd == "help":
            print(Fore.CYAN + HELP_TEXT + RST)

        elif cmd == "show config":
            from agent.setup_wizard import print_session_summary
            print_session_summary(session)

        elif cmd == "show last":
            if last_output:
                _display_generated_files(last_output)
            else:
                warn("No output generated yet in this session.")

        elif cmd == "list":
            _list_and_display_outputs()

        elif cmd.startswith("audit "):
            _run_audit(prompt[6:].strip(), session)

        # ── Destroy commands ───────────────────────────────────────────────
        elif cmd == "destroy last":
            if last_output:
                _run_destroy(last_output.output_dir, session)
            else:
                # Try to find the most recent output with state
                dirs = _list_output_dirs()
                deployed = [d for d in dirs if d["deployed"]]
                if deployed:
                    _run_destroy(deployed[-1]["path"], session)
                else:
                    warn("No deployed infrastructure found.")
                    info("Use: destroy <path>  e.g.  destroy ./outputs/aws_abc123")

        elif cmd.startswith("destroy "):
            path = prompt[8:].strip()
            _run_destroy(path, session)

        # ── Generate pipeline ──────────────────────────────────────────────
        else:
            last_output = _run_generation_pipeline(prompt, session, generator, parser)


# ─── List outputs ─────────────────────────────────────────────────────────────

def _list_and_display_outputs(base="./outputs"):
    section("INFRASTRUCTURE OUTPUTS", "📁")
    dirs = _list_output_dirs(base)
    if not dirs:
        warn("No output directories found.")
        info("Generate infrastructure first, then use 'destroy <path>' to tear it down.")
        return

    print(f"  {BRT}{Fore.WHITE}{'DIRECTORY':<30} {'TF FILES':<10} {'STATE':<10} {'RESOURCES'}{RST}")
    print(f"  {'─'*65}")
    for d in dirs:
        state_str = (f"{Fore.GREEN}deployed ({_get_resource_count(d['path']+'/terraform.tfstate')} resources){RST}"
                     if d["deployed"]
                     else (f"{Fore.YELLOW}state exists (empty){RST}" if d["has_state"]
                           else f"{Fore.WHITE}{DIM}no state (not deployed){RST}"))
        tf_str = f"{Fore.GREEN}yes{RST}" if d["has_tf"] else f"{Fore.RED}no{RST}"
        print(f"  {Fore.CYAN}{d['name']:<30}{RST} {tf_str:<20} {state_str}")
    print()
    info("To destroy: destroy ./outputs/<directory-name>")


# ─── Generation pipeline ──────────────────────────────────────────────────────

def _run_generation_pipeline(prompt, session, generator, parser):
    print()
    section("PROCESSING YOUR REQUEST", "⚙")
    info(f"Prompt: {BRT}{prompt}{RST}")
    print()

    # Stage 1: Parse intent
    working("Parsing intent...")
    time.sleep(0.3)
    try:
        intent = parser.parse(prompt, session)
    except Exception as e:
        error(f"Failed to parse prompt: {e}")
        return None

    _display_parsed_intent(intent, session)

    if not confirm("Is this what you want to generate?", default=True):
        warn("Cancelled. Try rephrasing your prompt.")
        return None

    # Stage 2: Generate IaC
    section("GENERATING IaC CODE", "📝")
    working(f"Generating {session.iac_tool.capitalize()} code for {session.cloud.upper()}...")
    time.sleep(0.4)

    try:
        result = generator.generate(intent, session)
    except Exception as e:
        error(f"Code generation failed: {e}")
        return None

    if not result.success:
        error(f"Generation failed: {result.error}")
        return None

    ok(f"Generated {len(result.files)} file(s)  ->  {result.output_dir}")
    print()
    _display_generated_files(result)

    # Stage 3: Guardrails
    section("GUARDRAIL CHECKS", "🛡")
    if result.security_issues:
        critical = [i for i in result.security_issues if i["severity"] == "CRITICAL"]
        high     = [i for i in result.security_issues if i["severity"] == "HIGH"]
        if critical:
            error("CRITICAL security issues found - deployment blocked!")
            for i in critical:
                error(f"  {i['description']}")
            return result
        if high:
            for i in high:
                warn(f"  {i['description']}")
            if not confirm("Proceed despite HIGH severity issues?", default=False):
                return result
    else:
        ok("All built-in guardrail checks passed")

    # Stage 4: Security scanning
    print()
    section("SECURITY SCANNING", "🔍")
    try:
        scan_results = run_all_scanners(result.output_dir, session.cloud, session.iac_tool)
    except Exception as e:
        warn(f"Scanner error (skipping): {e}")
        scan_results = {"critical": 0, "high": 0, "medium": 0, "low": 0,
                        "findings": [], "passed": True, "scanners_run": []}

    if scan_results["findings"]:
        print()
        findings_table(scan_results["findings"][:20])

    _display_scan_summary(scan_results)

    if scan_results["critical"] > 0:
        error(f"Deployment blocked: {scan_results['critical']} CRITICAL finding(s)")
        return result

    # Stage 5: Deploy decision
    print()
    section("DEPLOYMENT", "🚀")
    _display_deployment_plan(intent, session, result)

    choice = _ask_deploy_action(session.iac_tool)

    if choice == "deploy":
        _run_deployment(result.output_dir, session, intent)
    elif choice == "plan":
        _run_plan_only(result.output_dir, session)
    else:
        ok(f"Files saved to: {result.output_dir}")
        _print_manual_deploy_commands(result.output_dir, session)

    return result


# ─── Display helpers ──────────────────────────────────────────────────────────

def _display_parsed_intent(intent, session):
    section("PARSED INTENT", "🧠")
    items = [
        ("Cloud",          session.cloud.upper()),
        ("Region",         session.region),
        ("IaC Tool",       session.iac_tool.capitalize()),
        ("Resources",      ", ".join(intent.get("resource_types", []))),
        ("Instance Count", str(intent.get("instance_count", 1))),
        ("Instance Type",  intent.get("instance_type", "t3.micro")),
        ("Storage (GB)",   str(intent.get("volume_size", 20))),
        ("Environment",    intent.get("environment", "production")),
        ("Network CIDR",   intent.get("cidr", "10.0.0.0/16")),
        ("AZ Count",       str(intent.get("az_count", 2))),
        ("Security",       ", ".join(intent.get("security_features", []))),
    ]
    summary_box("Understood Request", items)


def _display_generated_files(result):
    for fpath in sorted(result.files):
        if not os.path.exists(fpath):
            continue
        try:
            lines   = open(fpath).read().splitlines()
            preview = lines[:40]
            if len(lines) > 40:
                preview.append(f"... ({len(lines) - 40} more lines)")
            code_block(f"📄 {os.path.basename(fpath)}  [{len(lines)} lines]", preview)
        except Exception:
            pass


def _display_scan_summary(scan_results):
    c  = scan_results.get("critical", 0)
    h  = scan_results.get("high", 0)
    m  = scan_results.get("medium", 0)
    lo = scan_results.get("low", 0)
    print(f"\n  {BRT}{Fore.WHITE}Security Scan Summary{RST}")
    print(f"  {'─'*50}")
    print(f"  {BRT}{Fore.RED if c else Fore.GREEN}CRITICAL: {c:<4}{RST}  "
          f"{BRT}{Fore.YELLOW if h else Fore.GREEN}HIGH: {h:<4}{RST}  "
          f"{Fore.CYAN}MEDIUM: {m:<4}{RST}  {Fore.WHITE}LOW: {lo}{RST}")
    print(f"  {'─'*50}")
    print(f"  {DIM}Scanners: {', '.join(scan_results.get('scanners_run', ['builtin']))}{RST}")
    if scan_results.get("passed", True):
        print(f"  {BRT}{Fore.GREEN}✓ SCAN PASSED{RST}")
    else:
        print(f"  {BRT}{Fore.RED}✗ SCAN FAILED - review findings before deploying{RST}")
    print()


def _display_deployment_plan(intent, session, result):
    print(f"  {BRT}{Fore.WHITE}What will be deployed:{RST}\n")
    for res in intent.get("resource_types", []):
        print(f"    {Fore.GREEN}+{RST}  {res}")
    print(f"\n  {DIM}Output directory: {result.output_dir}{RST}")
    print(f"  {DIM}State file:        {result.output_dir}/terraform.tfstate{RST}")
    print()


def _ask_deploy_action(tool):
    installed = _is_tool_installed(tool)
    tag = f"  [{tool} not installed]" if not installed else ""
    options = [
        ("Plan only",  f"Run '{tool} plan' - preview changes, nothing deployed{tag}"),
        ("Deploy now", f"Run '{tool} apply' - deploy to cloud{tag}"),
        ("Save only",  "Save files locally - deploy or destroy manually later"),
    ]
    idx, _ = choice_menu("What would you like to do?", options, icon="🚀")
    return ["plan", "deploy", "save"][idx]


# ─── Destroy ──────────────────────────────────────────────────────────────────

def _run_destroy(output_dir, session):
    """
    Safely destroy Terraform-managed infrastructure with multiple safeguards:
    1. Verify the directory and state file exist
    2. Show exactly what will be destroyed (resource count + list)
    3. Triple confirmation: warning → resource list → type 'yes' to confirm
    4. Run terraform destroy
    5. Audit log the destruction
    """
    tool = session.iac_tool

    section("DESTROY INFRASTRUCTURE", "💥")

    # ── Validate directory ─────────────────────────────────────────────────
    output_dir = os.path.abspath(output_dir)

    if not os.path.exists(output_dir):
        error(f"Directory not found: {output_dir}")
        info("Use 'list' to see available output directories.")
        return

    tf_files = list(Path(output_dir).glob("*.tf"))
    if not tf_files:
        error(f"No Terraform files found in: {output_dir}")
        info("This directory was not generated by this agent.")
        return

    state_file = os.path.join(output_dir, "terraform.tfstate")
    has_state  = os.path.exists(state_file)

    # ── Show what exists ───────────────────────────────────────────────────
    print(f"  {BRT}{Fore.WHITE}Target directory:{RST}  {Fore.CYAN}{output_dir}{RST}")
    print(f"  {BRT}{Fore.WHITE}Terraform files: {RST}  {len(tf_files)} file(s)")

    if has_state and _state_has_resources(state_file):
        resource_count = _get_resource_count(state_file)
        resource_names = _get_resource_names(state_file)
        print(f"  {BRT}{Fore.WHITE}State file:      {RST}  {Fore.GREEN}exists ({resource_count} managed resources){RST}")
        print()
        print(f"  {BRT}{Fore.RED}Resources that will be PERMANENTLY DESTROYED:{RST}\n")
        for name in resource_names[:25]:
            print(f"    {Fore.RED}-{RST}  {name}")
        if len(resource_names) > 25:
            print(f"    {Fore.RED}...{RST}  and {len(resource_names) - 25} more")
    elif has_state:
        print(f"  {BRT}{Fore.WHITE}State file:      {RST}  {Fore.YELLOW}exists (no resources - may already be destroyed){RST}")
        print()
        warn("State file is empty - infrastructure may already be destroyed.")
        if not confirm("Continue anyway?", default=False):
            info("Destroy cancelled.")
            return
    else:
        print(f"  {BRT}{Fore.WHITE}State file:      {RST}  {Fore.YELLOW}not found (never deployed or state was deleted){RST}")
        print()
        warn("No state file found. Terraform cannot destroy what it did not deploy.")
        warn("If you deployed this manually, you must destroy it manually too.")
        if not confirm("Run 'terraform destroy' anyway? (may do nothing)", default=False):
            info("Destroy cancelled.")
            return

    # ── Check tool installed ───────────────────────────────────────────────
    if not _is_tool_installed(tool):
        print()
        error(f"'{tool}' is not installed - cannot run destroy.")
        _print_manual_destroy_commands(output_dir, session)
        return

    # ── Safety confirmation 1: general warning ────────────────────────────
    print()
    print(f"  {BRT}{Fore.RED}{'!'*60}{RST}")
    print(f"  {BRT}{Fore.RED}  WARNING: This will PERMANENTLY DELETE all cloud resources{RST}")
    print(f"  {BRT}{Fore.RED}  listed above. This action CANNOT be undone.{RST}")
    print(f"  {BRT}{Fore.RED}{'!'*60}{RST}")
    print()

    if not confirm("Are you sure you want to destroy this infrastructure?", default=False):
        info("Destroy cancelled. No changes made.")
        return

    # ── Safety confirmation 2: type 'yes' explicitly ──────────────────────
    print()
    print(f"  {BRT}{Fore.YELLOW}Type  {Fore.RED}yes{Fore.YELLOW}  to confirm permanent destruction (anything else cancels):{RST}")
    try:
        typed = input(f"  {BRT}{Fore.RED}Confirm > {RST}").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print()
        info("Destroy cancelled.")
        return

    if typed != "yes":
        warn(f"You typed '{typed}' - destroy cancelled. No changes made.")
        return

    # ── Run destroy ────────────────────────────────────────────────────────
    print()
    section("RUNNING DESTROY", "💥")
    env = {**os.environ, **session.env_vars}

    try:
        # Init first (needed if .terraform/ dir is missing)
        working(f"Running {tool} init...")
        r = subprocess.run(
            [tool, "init", "-input=false"],
            cwd=output_dir, env=env,
            capture_output=True, text=True, timeout=120
        )
        if r.returncode != 0:
            error(f"{tool} init failed:")
            if r.stderr: print(f"  {Fore.RED}{r.stderr[-2000:]}{RST}")
            return
        ok("Init complete")

        # Destroy plan (show what will be removed)
        working(f"Running {tool} plan -destroy (preview)...")
        r = subprocess.run(
            [tool, "plan", "-destroy", "-input=false", "-out=destroy.tfplan"],
            cwd=output_dir, env=env,
            capture_output=True, text=True, timeout=300
        )
        if r.stdout:
            # Show last portion of plan output
            plan_lines = r.stdout.strip().splitlines()
            print()
            for line in plan_lines[-30:]:
                # Colour lines that show resource removal
                if line.strip().startswith("- "):
                    print(f"  {Fore.RED}{line}{RST}")
                elif "destroy" in line.lower() or "will be destroyed" in line.lower():
                    print(f"  {Fore.RED}{line}{RST}")
                elif "Plan:" in line:
                    print(f"  {BRT}{Fore.YELLOW}{line}{RST}")
                else:
                    print(f"  {DIM}{line}{RST}")
            print()

        if r.returncode != 0:
            error(f"{tool} plan -destroy failed:")
            if r.stderr: print(f"  {Fore.RED}{r.stderr[-2000:]}{RST}")
            return

        # Final confirmation after seeing the plan
        if not confirm("Destroy plan shown above. Execute destruction now?", default=False):
            info("Destroy cancelled after plan review. No changes made.")
            # Clean up the plan file
            try:
                os.remove(os.path.join(output_dir, "destroy.tfplan"))
            except Exception:
                pass
            return

        # Execute destroy
        working("Destroying infrastructure... (this may take several minutes)")
        r = subprocess.run(
            [tool, "apply", "-destroy", "-auto-approve", "destroy.tfplan"],
            cwd=output_dir, env=env,
            capture_output=True, text=True, timeout=900   # 15 min timeout
        )

        if r.stdout:
            # Show the output, highlighting destroyed resources
            for line in r.stdout.splitlines():
                if "Destroying..." in line or "Destruction complete" in line:
                    print(f"  {Fore.RED}{line}{RST}")
                elif "Destroy complete" in line:
                    print(f"  {BRT}{Fore.GREEN}{line}{RST}")
                elif "Error" in line:
                    print(f"  {BRT}{Fore.RED}{line}{RST}")
                else:
                    print(f"  {DIM}{line}{RST}")

        if r.returncode == 0:
            print()
            ok("Infrastructure destroyed successfully.")
            ok("All cloud resources have been removed.")
            _write_audit_log(output_dir, session, {}, "destroyed")
            print()
            info(f"Local files still exist at: {output_dir}")
            if confirm("Delete local output directory too?", default=False):
                shutil.rmtree(output_dir)
                ok(f"Deleted: {output_dir}")
            else:
                info("Local files kept. State file now reflects 0 resources.")
        else:
            error(f"{tool} destroy failed:")
            if r.stderr: print(f"  {Fore.RED}{r.stderr[-3000:]}{RST}")
            warn("Some resources may still exist in your cloud account.")
            warn("Check your cloud console and retry or destroy manually.")

    except subprocess.TimeoutExpired:
        error(f"{tool} destroy timed out after 15 minutes.")
        warn("Destruction may be partially complete. Check your cloud console.")
    except Exception as e:
        error(f"Unexpected error during destroy: {e}")


def _get_resource_names(state_path):
    """Extract human-readable resource names from state file."""
    names = []
    try:
        data = json.loads(open(state_path).read())
        for res in data.get("resources", []):
            rtype    = res.get("type", "unknown")
            rname    = res.get("name", "")
            provider = res.get("provider", "").split("/")[-1]
            names.append(f"{rtype}.{rname}")
    except Exception:
        pass
    return names


def _print_manual_destroy_commands(output_dir, session):
    tool  = session.iac_tool
    lines = [f"cd {output_dir}", ""]
    if session.env_vars:
        lines.append("# Export credentials:")
        for k, v in session.env_vars.items():
            masked = v[:4] + "****" if len(v) > 4 else "****"
            lines.append(f"export {k}='{masked}'")
        lines.append("")
    lines += [
        f"{tool} init",
        f"{tool} plan -destroy   # preview what will be removed",
        f"{tool} destroy         # destroy with interactive confirmation",
        f"# or:",
        f"{tool} apply -destroy -auto-approve   # destroy without prompt",
    ]
    code_block("Manual Destroy Commands", lines)


# ─── Deployment runners ───────────────────────────────────────────────────────

def _run_deployment(output_dir, session, intent):
    tool = session.iac_tool
    section("DEPLOYING INFRASTRUCTURE", "🚀")

    if not _check_tool_or_show_install(tool, output_dir, session):
        return

    warn("This will create real cloud resources and may incur costs.")
    if not confirm("Confirm deployment?", default=False):
        info("Deployment cancelled.")
        return

    env = {**os.environ, **session.env_vars}

    try:
        working(f"Running {tool} init...")
        r = subprocess.run([tool, "init", "-input=false"],
                           cwd=output_dir, env=env,
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            error(f"{tool} init failed:")
            if r.stderr: print(f"  {Fore.RED}{r.stderr[-2000:]}{RST}")
            return
        ok("Init complete")

        working(f"Running {tool} plan...")
        r = subprocess.run([tool, "plan", "-input=false", "-out=tfplan"],
                           cwd=output_dir, env=env,
                           capture_output=True, text=True, timeout=300)
        if r.stdout: print(r.stdout[-4000:])
        if r.returncode != 0:
            error(f"{tool} plan failed:")
            if r.stderr: print(f"  {Fore.RED}{r.stderr[-2000:]}{RST}")
            return

        if not confirm("Plan complete. Apply now?", default=False):
            info("Apply cancelled - no changes made.")
            return

        working("Applying...")
        r = subprocess.run([tool, "apply", "-input=false", "-auto-approve", "tfplan"],
                           cwd=output_dir, env=env,
                           capture_output=True, text=True, timeout=600)
        if r.stdout: print(r.stdout[-4000:])
        if r.returncode == 0:
            ok("Deployment complete!")
            ok(f"To destroy later: type  destroy {output_dir}")
            _write_audit_log(output_dir, session, intent, "deployed")
        else:
            error(f"{tool} apply failed:")
            if r.stderr: print(f"  {Fore.RED}{r.stderr[-2000:]}{RST}")

    except subprocess.TimeoutExpired:
        error(f"{tool} timed out.")
    except Exception as e:
        error(f"Unexpected error: {e}")


def _run_plan_only(output_dir, session):
    tool = session.iac_tool
    section("PLAN (DRY RUN)", "📋")

    if not _check_tool_or_show_install(tool, output_dir, session):
        return

    env = {**os.environ, **session.env_vars}

    try:
        working(f"Running {tool} init...")
        r = subprocess.run([tool, "init", "-input=false"],
                           cwd=output_dir, env=env,
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            error(f"{tool} init failed:")
            if r.stderr: print(f"  {Fore.RED}{r.stderr[-2000:]}{RST}")
            info("Check your credentials and network connection.")
            return
        ok("Init complete")

        working(f"Running {tool} plan...")
        r = subprocess.run([tool, "plan", "-input=false"],
                           cwd=output_dir, env=env,
                           capture_output=True, text=True, timeout=300)
        if r.stdout: print(r.stdout[-5000:])
        if r.returncode == 0:
            ok("Plan complete - no changes applied to cloud.")
        else:
            error(f"{tool} plan failed:")
            if r.stderr: print(f"  {Fore.RED}{r.stderr[-2000:]}{RST}")
            info("Common causes: invalid credentials, missing permissions, network issue.")

    except subprocess.TimeoutExpired:
        error(f"{tool} plan timed out.")
    except Exception as e:
        error(f"Unexpected error: {e}")


# ─── Audit, manual commands, examples ────────────────────────────────────────

def _run_audit(path, session):
    if not os.path.exists(path):
        error(f"Path not found: {path}")
        return
    section(f"AUDITING: {path}", "🔍")
    try:
        results = run_all_scanners(path, session.cloud, session.iac_tool)
        if results["findings"]:
            findings_table(results["findings"])
        _display_scan_summary(results)
    except Exception as e:
        error(f"Audit failed: {e}")


def _print_manual_deploy_commands(output_dir, session):
    tool  = session.iac_tool
    lines = [f"cd {output_dir}", ""]
    if session.env_vars:
        lines.append("# Export credentials (replace **** with actual values):")
        for k, v in session.env_vars.items():
            masked = v[:4] + "****" if len(v) > 4 else "****"
            lines.append(f"export {k}='{masked}'")
        lines.append("")
    lines += [f"{tool} init", f"{tool} plan", f"{tool} apply"]
    code_block("Step 2 - Deploy manually", lines)


def _print_prompt_examples(cloud):
    examples = {
        "aws":   [
            "make secure infra with 1 private instance in mumbai region",
            "create production vpc with 2 private subnets and encrypted storage",
            "deploy 3 t3.small instances private no public ip",
        ],
        "gcp":   [
            "create private vpc with 1 e2-micro instance in mumbai",
            "deploy secure gke cluster with network policies",
        ],
        "azure": [
            "create secure vnet with 1 private vm in central india",
            "setup private linux vm with managed identity",
        ],
    }
    print(f"  {BRT}{Fore.YELLOW}💡 Example prompts for {cloud.upper()}:{RST}\n")
    for ex in examples.get(cloud, []):
        print(f"    {DIM}>{RST}  {Fore.WHITE}{ex}{RST}")
    print()


# ─── Audit log ────────────────────────────────────────────────────────────────

def _write_audit_log(output_dir, session, intent, action):
    try:
        os.makedirs("./logs", exist_ok=True)
        entry = {
            "timestamp":   datetime.datetime.utcnow().isoformat(),
            "action":      action,
            "cloud":       session.cloud,
            "region":      session.region,
            "iac_tool":    session.iac_tool,
            "output_dir":  output_dir,
            "intent_hash": hashlib.sha256(
                json.dumps(intent, default=str).encode()).hexdigest(),
            "compliance":  session.compliance_targets,
        }
        with open("./logs/audit.jsonl", "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


# ─── Goodbye ─────────────────────────────────────────────────────────────────

def _print_goodbye():
    print(f"\n  {BRT}{Fore.CYAN}╔{'═'*48}╗{RST}")
    print(f"  {BRT}{Fore.CYAN}║{RST}  {Fore.GREEN}Thanks for using Local AI DevSecOps Agent!{Fore.CYAN}  ║{RST}")
    print(f"  {BRT}{Fore.CYAN}║{RST}  {DIM}All credentials cleared from memory.{RST}{Fore.CYAN}        ║{RST}")
    print(f"  {BRT}{Fore.CYAN}╚{'═'*48}╝{RST}\n")
