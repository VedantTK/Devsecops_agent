"""
agent_loop.py
Main interactive prompt loop.
Handles: generate → scan → fix vulns → modify → deploy → modify live → destroy
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
from dataclasses import dataclass, field
from typing import Optional, List

from agent.terminal_ui import (
    section, step, info, ok, warn, error, working,
    choice_menu, text_input, confirm,
    code_block, summary_box, findings_table,
    print_banner, scanning_block,
    Fore, BRT, RST, DIM, Style
)
from agent.iac_generator import IaCGenerator, IntentParser
from agent.security_scanner import run_all_scanners
from agent.iac_patcher import IaCPatcher


# ─── Active context ───────────────────────────────────────────────────────────
# Tracks the currently active output directory across the session.
# Commands like "fix", "modify", "plan", "deploy" all operate on this context.

@dataclass
class ActiveContext:
    output_dir: str                    # path to the active output dir
    intent: dict = field(default_factory=dict)
    last_scan: dict = field(default_factory=dict)
    is_deployed: bool = False          # True once terraform apply succeeded
    generation_result: object = None   # GenerationResult object


HELP_TEXT = """
  AVAILABLE COMMANDS
  ──────────────────────────────────────────────────────────────────
  GENERATE
    <any prompt>            Generate new secure infrastructure
    e.g. "make 1 private ec2 in mumbai"

  MODIFY / FIX (operates on current active IaC)
    fix vulnerabilities     Auto-fix all scanner findings in active code
    fix <finding>           Fix a specific issue, e.g. "fix encryption"
    modify <instruction>    Change the active code, e.g. "modify: change instance type to t3.large"
    show diff               Show what changed since last patch
    undo patch              Restore code to state before last patch
    rescan                  Re-run security scanners on active code
    replan                  Re-run terraform plan on active code

  VIEW
    show last               Show active IaC file contents
    show context            Show the currently active output directory
    list                    List all output directories with state

  DEPLOY (operates on current active IaC)
    plan                    Run terraform plan on active code
    deploy                  Run terraform apply on active code
    deploy <path>           Deploy a specific output directory

  DESTROY
    destroy                 Destroy the currently active infrastructure
    destroy last            Destroy the most recently deployed infra
    destroy <path>          Destroy a specific output directory

  AUDIT
    audit <path>            Run security audit on any IaC path
    audit current           Audit the currently active code

  OTHER
    show config             Show session configuration
    help                    Show this help
    exit / quit             Exit
  ──────────────────────────────────────────────────────────────────

  MODIFY EXAMPLES
    modify: change instance type to t3.large
    modify: increase storage to 100gb
    modify: disable public access
    modify: enable encryption
    modify: change instance count to 3
    modify: set retention to 365 days
    modify: change region to us-east-1
"""

INSTALL_HINTS = {
    "terraform": [
        "# Option 1 - Official installer (Linux/macOS)",
        "wget https://releases.hashicorp.com/terraform/1.7.5/terraform_1.7.5_linux_amd64.zip",
        "unzip terraform_1.7.5_linux_amd64.zip && sudo mv terraform /usr/local/bin/",
        "",
        "# Option 2 - Homebrew (macOS)",
        "brew tap hashicorp/tap && brew install hashicorp/tap/terraform",
        "",
        "# Option 3 - tfenv",
        "git clone https://github.com/tfutils/tfenv.git ~/.tfenv",
        "ln -s ~/.tfenv/bin/* /usr/local/bin/ && tfenv install latest",
    ],
    "pulumi": [
        "curl -fsSL https://get.pulumi.com | sh",
        "brew install pulumi/tap/pulumi",
    ],
}


# ─── Tool check ──────────────────────────────────────────────────────────────

def _is_tool_installed(tool):
    return shutil.which(tool) is not None


def _check_tool_or_show_install(tool, output_dir, session):
    if _is_tool_installed(tool):
        return True
    print()
    error(f"'{tool}' is not installed or not found in your PATH.")
    hints = INSTALL_HINTS.get(tool, [])
    code_block(f"Install {tool.capitalize()}", hints)
    _print_manual_deploy_commands(output_dir, session)
    return False


# ─── Output directory helpers ─────────────────────────────────────────────────

def _list_output_dirs(base="./outputs"):
    dirs = []
    if not os.path.exists(base):
        return dirs
    for entry in sorted(Path(base).iterdir()):
        if not entry.is_dir():
            continue
        has_tf    = any(entry.glob("*.tf"))
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
    try:
        data = json.loads(open(state_path).read())
        return len(data.get("resources", [])) > 0
    except Exception:
        return False


def _get_resource_count(state_path):
    try:
        return len(json.loads(open(state_path).read()).get("resources", []))
    except Exception:
        return 0


def _get_resource_names(state_path):
    names = []
    try:
        for res in json.loads(open(state_path).read()).get("resources", []):
            names.append(f"{res.get('type','unknown')}.{res.get('name','')}")
    except Exception:
        pass
    return names


# ─── Main agent loop ─────────────────────────────────────────────────────────

def run_agent_loop(session):
    generator   = IaCGenerator(output_base="./outputs")
    parser      = IntentParser()
    patcher     = IaCPatcher()
    ctx: Optional[ActiveContext] = None   # active IaC context

    tool = session.iac_tool
    if not _is_tool_installed(tool):
        warn(f"'{tool}' not installed - generation works but Plan/Deploy will be skipped.")

    section("AGENT READY", "🤖")
    inst = f"{Fore.GREEN}installed{RST}" if _is_tool_installed(tool) else f"{Fore.RED}not installed{RST}"
    print(f"  {BRT}{Fore.GREEN}DevSecOps Agent ready.{RST}  "
          f"{DIM}Cloud: {session.cloud.upper()} | Region: {session.region} | "
          f"{session.iac_tool.capitalize()} ({inst}{DIM}){RST}")
    print(f"  {DIM}Type 'help' for all commands.{RST}\n")
    _print_prompt_examples(session.cloud)

    while True:
        # Show active context in prompt if one is set
        ctx_hint = ""
        if ctx:
            deployed_flag = f" {Fore.GREEN}[deployed]{RST}" if ctx.is_deployed else f" {Fore.YELLOW}[not deployed]{RST}"
            dir_name = os.path.basename(ctx.output_dir)
            ctx_hint = f"{Fore.WHITE}({dir_name}{deployed_flag}{Fore.WHITE}){RST} "

        try:
            prompt = input(
                f"\n  {BRT}{Fore.CYAN}devsecops{Fore.WHITE}@{Fore.GREEN}{session.cloud} "
                f"{ctx_hint}{Fore.WHITE}> {RST}"
            ).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            if confirm("Exit?", default=True):
                _print_goodbye()
                sys.exit(0)
            continue

        if not prompt:
            continue

        cmd = prompt.lower().strip()

        # ── Navigation ────────────────────────────────────────────────────
        if cmd in ("exit", "quit", "q", "bye"):
            _print_goodbye()
            break

        elif cmd == "help":
            print(Fore.CYAN + HELP_TEXT + RST)

        elif cmd == "show config":
            from agent.setup_wizard import print_session_summary
            print_session_summary(session)

        elif cmd in ("show last", "show current"):
            if ctx:
                _display_dir_files(ctx.output_dir)
            else:
                warn("No active IaC context. Generate infrastructure first.")

        elif cmd == "show context":
            _show_active_context(ctx)

        elif cmd == "list":
            _list_and_display_outputs()

        elif cmd in ("audit current", "scan current"):
            if ctx:
                ctx = _run_rescan(ctx, session)
            else:
                warn("No active context. Generate infrastructure first.")

        elif cmd.startswith("audit "):
            _run_audit(prompt[6:].strip(), session)

        # ── Fix / Modify ──────────────────────────────────────────────────
        elif cmd in ("fix vulnerabilities", "fix vulns", "fix all", "fix issues"):
            if not ctx:
                warn("No active IaC context. Generate infrastructure first.")
            else:
                ctx = _run_fix_vulnerabilities(ctx, session, patcher)

        elif cmd.startswith("fix "):
            if not ctx:
                warn("No active IaC context. Generate infrastructure first.")
            else:
                # "fix encryption" / "fix public access" etc.
                what = prompt[4:].strip()
                ctx = _run_fix_specific(ctx, session, patcher, what)

        elif cmd.startswith("modify:") or cmd.startswith("modify "):
            if not ctx:
                warn("No active IaC context. Generate infrastructure first.")
            else:
                instruction = prompt.split(":", 1)[-1].strip() if ":" in prompt else prompt[7:].strip()
                ctx = _run_modify(ctx, session, patcher, instruction)

        elif cmd == "show diff":
            if ctx:
                _show_diff(ctx, patcher)
            else:
                warn("No active context.")

        elif cmd in ("undo patch", "undo", "restore"):
            if ctx:
                _run_undo(ctx, patcher)
            else:
                warn("No active context.")

        elif cmd in ("rescan", "re-scan", "scan"):
            if ctx:
                ctx = _run_rescan(ctx, session)
            else:
                warn("No active context. Generate first.")

        # ── Plan / Deploy ─────────────────────────────────────────────────
        elif cmd in ("plan", "replan", "re-plan"):
            if ctx:
                _run_plan_only(ctx.output_dir, session)
            else:
                warn("No active context. Generate infrastructure first.")

        elif cmd == "deploy":
            if ctx:
                ctx = _run_deploy_active(ctx, session)
            else:
                warn("No active context. Generate infrastructure first.")

        elif cmd.startswith("deploy "):
            path = prompt[7:].strip()
            _run_deployment(path, session, {})

        # ── Destroy ───────────────────────────────────────────────────────
        elif cmd == "destroy":
            if ctx:
                _run_destroy(ctx.output_dir, session)
            else:
                warn("No active context. Use: destroy <path>")

        elif cmd == "destroy last":
            dirs = _list_output_dirs()
            deployed = [d for d in dirs if d["deployed"]]
            if deployed:
                _run_destroy(deployed[-1]["path"], session)
            else:
                warn("No deployed infrastructure found.")

        elif cmd.startswith("destroy "):
            _run_destroy(prompt[8:].strip(), session)

        # ── Generate ─────────────────────────────────────────────────────
        else:
            result = _run_generation_pipeline(prompt, session, generator, parser)
            if result:
                ctx = ActiveContext(
                    output_dir=result.output_dir,
                    intent=result.intent if hasattr(result, 'intent') else {},
                    generation_result=result
                )
                # Run initial scan and store in context
                try:
                    scan = run_all_scanners(ctx.output_dir, session.cloud, session.iac_tool)
                    ctx.last_scan = scan
                except Exception:
                    pass


# ─── Fix vulnerabilities ──────────────────────────────────────────────────────

def _run_fix_vulnerabilities(ctx: ActiveContext, session, patcher: IaCPatcher) -> ActiveContext:
    section("AUTO-FIX VULNERABILITIES", "🔧")

    findings = ctx.last_scan.get("findings", [])
    if not findings:
        # No cached scan — run one now
        info("No cached scan found. Running scanner first...")
        ctx = _run_rescan(ctx, session)
        findings = ctx.last_scan.get("findings", [])

    if not findings:
        ok("No findings to fix — code is already clean!")
        return ctx

    # Show what we're going to fix
    fixable = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")]
    print(f"\n  {BRT}{Fore.WHITE}Findings to auto-fix ({len(fixable)} of {len(findings)}):{RST}\n")
    for f in fixable[:15]:
        sev_col = Fore.RED if f["severity"] == "CRITICAL" else (Fore.YELLOW if f["severity"] == "HIGH" else Fore.CYAN)
        print(f"    {sev_col}{f['severity']:<8}{RST}  {f.get('description','')[:70]}")
    if len(fixable) > 15:
        print(f"    ... and {len(fixable)-15} more")
    print()

    if not confirm(f"Auto-fix these {len(fixable)} finding(s)?", default=True):
        info("Fix cancelled.")
        return ctx

    working("Applying fixes...")
    result = patcher.fix_vulnerabilities(ctx.output_dir, fixable)

    if result.success and result.changes:
        print()
        ok(f"Applied {len(result.changes)} fix(es):")
        for change in result.changes:
            print(f"    {Fore.GREEN}+{RST}  {change}")
        print()

        # Re-scan after fixing
        if confirm("Re-run security scan to verify fixes?", default=True):
            ctx = _run_rescan(ctx, session)

        # Ask what to do next
        ctx = _ask_next_action_after_patch(ctx, session)
    else:
        warn("No automatic fixes could be applied.")
        info("Try: modify: <specific instruction>  e.g.  modify: enable encryption")

    return ctx


def _run_fix_specific(ctx: ActiveContext, session, patcher: IaCPatcher, what: str) -> ActiveContext:
    """Fix a specific thing: 'fix encryption', 'fix public access', etc."""
    section(f"FIX: {what.upper()}", "🔧")

    working(f"Applying fix for: {what}...")
    # Treat it as a modify prompt with "enable/fix" prefix
    result = patcher.apply_prompt_patch(ctx.output_dir, f"enable {what}")

    if not result.success:
        # Try direct patch
        result = patcher.apply_prompt_patch(ctx.output_dir, what)

    if result.success and result.patched_files:
        ok(f"Fixed:")
        for change in result.changes:
            print(f"    {Fore.GREEN}+{RST}  {change}")
        print()
        ctx = _ask_next_action_after_patch(ctx, session)
    else:
        warn(f"Could not automatically fix: '{what}'")
        info("Try a more specific prompt:")
        info("  modify: enable encryption")
        info("  modify: disable public access")
        info("  modify: change instance type to t3.large")

    return ctx


# ─── Modify ───────────────────────────────────────────────────────────────────

def _run_modify(ctx: ActiveContext, session, patcher: IaCPatcher, instruction: str) -> ActiveContext:
    section("MODIFYING IaC CODE", "✏️")

    is_deployed = ctx.is_deployed
    if is_deployed:
        print(f"  {BRT}{Fore.YELLOW}Note: This infrastructure is already deployed.{RST}")
        print(f"  {DIM}Changes will be applied to the code and you can run 'deploy' to")
        print(f"  update the live infrastructure incrementally (terraform apply).{RST}")
        print()

    info(f"Instruction: {BRT}{instruction}{RST}")
    info(f"Target dir:  {DIM}{ctx.output_dir}{RST}")
    print()

    if not confirm("Apply this modification?", default=True):
        info("Modification cancelled.")
        return ctx

    working("Patching IaC code...")
    result = patcher.apply_prompt_patch(ctx.output_dir, instruction)

    if not result.success:
        error(f"Could not apply patch: {result.error}")
        return ctx

    ok(f"Modified {len(result.patched_files)} file(s):")
    for change in result.changes:
        print(f"    {Fore.GREEN}~{RST}  {change}")
    print()

    # Show diff
    diff_lines = patcher.get_diff(ctx.output_dir)
    if diff_lines and diff_lines != ["  (no diff available)"]:
        code_block("Changes (before/after)", diff_lines[:40])
        print()

    # Re-scan to check the modified code
    if confirm("Re-scan modified code for vulnerabilities?", default=True):
        ctx = _run_rescan(ctx, session)

    ctx = _ask_next_action_after_patch(ctx, session)
    return ctx


# ─── Ask next action after any patch ─────────────────────────────────────────

def _ask_next_action_after_patch(ctx: ActiveContext, session) -> ActiveContext:
    """After a fix or modify, ask what the user wants to do next."""
    tool = session.iac_tool
    print()

    if ctx.is_deployed:
        options = [
            ("Re-plan",         f"Run '{tool} plan' to preview incremental changes"),
            ("Apply update",    f"Run '{tool} apply' to update live infrastructure"),
            ("View code",       "Show the modified IaC files"),
            ("Nothing yet",     "I'll decide later"),
        ]
        idx, _ = choice_menu("Infrastructure is deployed. What next?", options, icon="⚡")
        if idx == 0:
            _run_plan_only(ctx.output_dir, session)
        elif idx == 1:
            ctx = _run_deploy_active(ctx, session)
        elif idx == 2:
            _display_dir_files(ctx.output_dir)
    else:
        options = [
            ("Re-plan",     f"Run '{tool} plan' to preview changes"),
            ("Deploy now",  f"Run '{tool} apply' to deploy"),
            ("View code",   "Show the modified IaC files"),
            ("Nothing yet", "I'll decide later"),
        ]
        idx, _ = choice_menu("What would you like to do next?", options, icon="🚀")
        if idx == 0:
            _run_plan_only(ctx.output_dir, session)
        elif idx == 1:
            ctx = _run_deploy_active(ctx, session)
        elif idx == 2:
            _display_dir_files(ctx.output_dir)

    return ctx


# ─── Rescan ───────────────────────────────────────────────────────────────────

def _run_rescan(ctx: ActiveContext, session) -> ActiveContext:
    section("RE-SCANNING", "🔍")
    working("Running security scanners...")
    try:
        scan = run_all_scanners(ctx.output_dir, session.cloud, session.iac_tool)
        ctx.last_scan = scan
        if scan["findings"]:
            findings_table(scan["findings"][:20])
        _display_scan_summary(scan)

        if (scan["critical"] > 0 or scan["high"] > 0) and not ctx.is_deployed:
            if confirm("Fix remaining vulnerabilities automatically?", default=True):
                from agent.iac_patcher import IaCPatcher
                patcher = IaCPatcher()
                ctx = _run_fix_vulnerabilities(ctx, session, patcher)
    except Exception as e:
        error(f"Scan failed: {e}")
    return ctx


# ─── Show diff ────────────────────────────────────────────────────────────────

def _show_diff(ctx: ActiveContext, patcher: IaCPatcher):
    section("CODE DIFF", "📊")
    diff_lines = patcher.get_diff(ctx.output_dir)
    if diff_lines == ["  (no diff available)"]:
        info("No backup found — no patches applied yet, or backup was cleared.")
    else:
        code_block("Changes (- before  /  + after)", diff_lines)


def _run_undo(ctx: ActiveContext, patcher: IaCPatcher):
    section("UNDO PATCH", "↩️")
    warn("This will restore the code to the state before the last patch.")
    if not confirm("Restore backup?", default=False):
        info("Undo cancelled.")
        return
    if patcher.restore_backup(ctx.output_dir):
        ok("Code restored from backup.")
        info("Run 'rescan' to verify, then 'plan' or 'deploy' to apply.")
    else:
        warn("No backup found — nothing to restore.")


# ─── Active context deploy ────────────────────────────────────────────────────

def _run_deploy_active(ctx: ActiveContext, session) -> ActiveContext:
    _run_deployment(ctx.output_dir, session, ctx.intent)
    state = os.path.join(ctx.output_dir, "terraform.tfstate")
    if os.path.exists(state) and _state_has_resources(state):
        ctx.is_deployed = True
    return ctx


# ─── Show active context ──────────────────────────────────────────────────────

def _show_active_context(ctx: Optional[ActiveContext]):
    section("ACTIVE CONTEXT", "📍")
    if not ctx:
        warn("No active context. Generate infrastructure to set one.")
        return
    status = f"{Fore.GREEN}DEPLOYED{RST}" if ctx.is_deployed else f"{Fore.YELLOW}NOT DEPLOYED{RST}"
    items = [
        ("Output Dir",   ctx.output_dir),
        ("Status",       status),
        ("Last Scan",    f"C:{ctx.last_scan.get('critical',0)} H:{ctx.last_scan.get('high',0)} "
                         f"M:{ctx.last_scan.get('medium',0)} L:{ctx.last_scan.get('low',0)}"
                         if ctx.last_scan else "not run"),
    ]
    summary_box("Active IaC Context", items)
    print()
    info("Commands operate on this directory:")
    print(f"    fix vulnerabilities   — auto-fix scanner findings")
    print(f"    modify: <instruction> — make changes to the code")
    print(f"    plan                  — preview changes")
    print(f"    deploy                — apply to cloud")
    print(f"    rescan                — re-run security scan")


# ─── Generation pipeline ──────────────────────────────────────────────────────

def _run_generation_pipeline(prompt, session, generator, parser):
    print()
    section("PROCESSING YOUR REQUEST", "⚙")
    info(f"Prompt: {BRT}{prompt}{RST}")
    print()

    working("Parsing intent...")
    time.sleep(0.3)
    try:
        intent = parser.parse(prompt, session)
    except Exception as e:
        error(f"Failed to parse: {e}")
        return None

    _display_parsed_intent(intent, session)
    if not confirm("Generate this infrastructure?", default=True):
        warn("Cancelled.")
        return None

    section("GENERATING IaC CODE", "📝")
    working(f"Generating {session.iac_tool.capitalize()} for {session.cloud.upper()}...")
    time.sleep(0.4)

    try:
        result = generator.generate(intent, session)
    except Exception as e:
        error(f"Generation failed: {e}")
        return None

    if not result.success:
        error(f"Generation failed: {result.error}")
        return None

    ok(f"Generated {len(result.files)} file(s)  ->  {result.output_dir}")
    print()
    _display_dir_files(result.output_dir)

    # Guardrails
    section("GUARDRAIL CHECKS", "🛡")
    if result.security_issues:
        critical = [i for i in result.security_issues if i["severity"] == "CRITICAL"]
        high     = [i for i in result.security_issues if i["severity"] == "HIGH"]
        if critical:
            error("CRITICAL issues found - deployment blocked!")
            for i in critical: error(f"  {i['description']}")
            return result
        if high:
            for i in high: warn(f"  {i['description']}")
            if not confirm("Proceed despite HIGH issues?", default=False):
                return result
    else:
        ok("All guardrail checks passed")

    # Security scanning
    print()
    section("SECURITY SCANNING", "🔍")
    try:
        scan_results = run_all_scanners(result.output_dir, session.cloud, session.iac_tool)
    except Exception as e:
        warn(f"Scanner error: {e}")
        scan_results = {"critical":0,"high":0,"medium":0,"low":0,"findings":[],"passed":True,"scanners_run":[]}

    if scan_results["findings"]:
        print()
        findings_table(scan_results["findings"][:20])
    _display_scan_summary(scan_results)

    # Auto-offer fix if vulnerabilities found
    if scan_results["critical"] > 0 or scan_results["high"] > 0:
        print()
        print(f"  {BRT}{Fore.YELLOW}Vulnerabilities found before deployment.{RST}")
        options = [
            ("Fix now",     "Auto-fix all scanner findings, then re-plan"),
            ("Skip fix",    "Continue to deployment options without fixing"),
            ("Cancel",      "Cancel and review manually"),
        ]
        idx, _ = choice_menu("What would you like to do?", options, icon="🛡")
        if idx == 0:
            # Store result so fix can use it
            tmp_ctx = ActiveContext(output_dir=result.output_dir, last_scan=scan_results)
            from agent.iac_patcher import IaCPatcher
            patcher = IaCPatcher()
            tmp_ctx = _run_fix_vulnerabilities(tmp_ctx, session, patcher)
            scan_results = tmp_ctx.last_scan
        elif idx == 2:
            info("Cancelled. Files saved at: " + result.output_dir)
            return result

    # Deployment decision
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
        info("Commands available:")
        print(f"    modify: <instruction>   — change the code")
        print(f"    fix vulnerabilities     — auto-fix scanner findings")
        print(f"    plan                    — preview changes")
        print(f"    deploy                  — deploy to cloud")

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
        ("Security",       ", ".join(intent.get("security_features", []))),
    ]
    summary_box("Understood Request", items)


def _display_dir_files(output_dir: str):
    for fpath in sorted(Path(output_dir).glob("*.tf")):
        try:
            lines   = open(fpath).read().splitlines()
            preview = lines[:40]
            if len(lines) > 40:
                preview.append(f"... ({len(lines)-40} more lines)")
            code_block(f"📄 {fpath.name}  [{len(lines)} lines]", preview)
        except Exception:
            pass


def _display_scan_summary(scan_results):
    c  = scan_results.get("critical",0)
    h  = scan_results.get("high",0)
    m  = scan_results.get("medium",0)
    lo = scan_results.get("low",0)
    print(f"\n  {BRT}Security Scan{RST}  "
          f"{BRT}{Fore.RED if c else Fore.GREEN}CRITICAL:{c}{RST}  "
          f"{BRT}{Fore.YELLOW if h else Fore.GREEN}HIGH:{h}{RST}  "
          f"{Fore.CYAN}MEDIUM:{m}{RST}  LOW:{lo}")
    print(f"  {DIM}Scanners: {', '.join(scan_results.get('scanners_run',['builtin']))}{RST}")
    if scan_results.get("passed", True):
        print(f"  {BRT}{Fore.GREEN}✓ SCAN PASSED{RST}")
    else:
        print(f"  {BRT}{Fore.RED}✗ SCAN FAILED{RST}")
    print()


def _display_deployment_plan(intent, session, result):
    print(f"  {BRT}What will be deployed:{RST}\n")
    for res in intent.get("resource_types", []):
        print(f"    {Fore.GREEN}+{RST}  {res}")
    print(f"\n  {DIM}Directory: {result.output_dir}{RST}\n")


def _ask_deploy_action(tool):
    tag = f" [{tool} not installed]" if not _is_tool_installed(tool) else ""
    options = [
        ("Plan only",  f"'{tool} plan' - preview, no changes{tag}"),
        ("Deploy now", f"'{tool} apply' - deploy to cloud{tag}"),
        ("Save only",  "Save files, deploy later"),
    ]
    idx, _ = choice_menu("What would you like to do?", options, icon="🚀")
    return ["plan", "deploy", "save"][idx]


def _list_and_display_outputs(base="./outputs"):
    section("OUTPUT DIRECTORIES", "📁")
    dirs = _list_output_dirs(base)
    if not dirs:
        warn("No output directories found.")
        return
    print(f"  {BRT}{'DIRECTORY':<30} {'DEPLOYED':<12} RESOURCES{RST}")
    print(f"  {'─'*60}")
    for d in dirs:
        dep = f"{Fore.GREEN}yes ({_get_resource_count(d['path']+'/terraform.tfstate')}){RST}" \
              if d["deployed"] else f"{Fore.WHITE}{DIM}no{RST}"
        print(f"  {Fore.CYAN}{d['name']:<30}{RST} {dep}")
    print()


# ─── Deployment / Plan / Destroy ──────────────────────────────────────────────

def _run_deployment(output_dir, session, intent):
    tool = session.iac_tool
    section("DEPLOYING", "🚀")
    if not _check_tool_or_show_install(tool, output_dir, session):
        return

    # Check if already deployed — if so this is an UPDATE
    state_file = os.path.join(output_dir, "terraform.tfstate")
    if os.path.exists(state_file) and _state_has_resources(state_file):
        n = _get_resource_count(state_file)
        print(f"  {BRT}{Fore.YELLOW}This directory has {n} deployed resources.{RST}")
        print(f"  {DIM}Terraform will compute a diff and only change what's needed.{RST}\n")
        warn("Running terraform apply will UPDATE existing cloud resources.")
    else:
        warn("This will CREATE new cloud resources and may incur costs.")

    if not confirm("Confirm?", default=False):
        info("Cancelled.")
        return

    env = {**os.environ, **session.env_vars}
    try:
        working(f"{tool} init...")
        r = subprocess.run([tool,"init","-input=false"], cwd=output_dir, env=env,
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            error(f"init failed:"); print(f"  {Fore.RED}{r.stderr[-2000:]}{RST}"); return
        ok("Init complete")

        working(f"{tool} plan...")
        r = subprocess.run([tool,"plan","-input=false","-out=tfplan"], cwd=output_dir, env=env,
                           capture_output=True, text=True, timeout=300)
        if r.stdout: print(r.stdout[-4000:])
        if r.returncode != 0:
            error(f"plan failed:"); print(f"  {Fore.RED}{r.stderr[-2000:]}{RST}"); return

        if not confirm("Plan complete. Apply now?", default=False):
            info("Apply cancelled."); return

        working("Applying...")
        r = subprocess.run([tool,"apply","-input=false","-auto-approve","tfplan"],
                           cwd=output_dir, env=env, capture_output=True, text=True, timeout=600)
        if r.stdout: print(r.stdout[-4000:])
        if r.returncode == 0:
            ok("Deployment complete!")
            ok(f"To modify: type  modify: <instruction>")
            ok(f"To destroy: type  destroy")
            _write_audit_log(output_dir, session, intent, "deployed")
        else:
            error("apply failed:"); print(f"  {Fore.RED}{r.stderr[-2000:]}{RST}")
    except subprocess.TimeoutExpired:
        error("Timed out.")
    except Exception as e:
        error(f"Unexpected error: {e}")


def _run_plan_only(output_dir, session):
    tool = session.iac_tool
    section("PLAN (DRY RUN)", "📋")
    if not _check_tool_or_show_install(tool, output_dir, session):
        return
    env = {**os.environ, **session.env_vars}
    try:
        working(f"{tool} init...")
        r = subprocess.run([tool,"init","-input=false"], cwd=output_dir, env=env,
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            error("init failed:"); print(f"  {Fore.RED}{r.stderr[-1500:]}{RST}"); return
        ok("Init complete")

        working(f"{tool} plan...")
        r = subprocess.run([tool,"plan","-input=false"], cwd=output_dir, env=env,
                           capture_output=True, text=True, timeout=300)
        if r.stdout: print(r.stdout[-5000:])
        if r.returncode == 0:
            ok("Plan complete - no changes applied.")
            info("If satisfied: type 'deploy'   If you want changes: type 'modify: <instruction>'")
        else:
            error("plan failed:"); print(f"  {Fore.RED}{r.stderr[-2000:]}{RST}")
    except subprocess.TimeoutExpired:
        error("Plan timed out.")
    except Exception as e:
        error(f"Unexpected: {e}")


def _run_audit(path, session):
    if not os.path.exists(path):
        error(f"Path not found: {path}"); return
    section(f"AUDITING: {path}", "🔍")
    try:
        results = run_all_scanners(path, session.cloud, session.iac_tool)
        if results["findings"]:
            findings_table(results["findings"])
        _display_scan_summary(results)
    except Exception as e:
        error(f"Audit failed: {e}")


def _run_destroy(output_dir, session):
    tool = session.iac_tool
    section("DESTROY INFRASTRUCTURE", "💥")
    output_dir = os.path.abspath(output_dir)

    if not os.path.exists(output_dir):
        error(f"Directory not found: {output_dir}"); return
    if not list(Path(output_dir).glob("*.tf")):
        error(f"No .tf files in: {output_dir}"); return
    if not _is_tool_installed(tool):
        error(f"'{tool}' not installed.")
        _print_manual_destroy_commands(output_dir, session); return

    state_file = os.path.join(output_dir, "terraform.tfstate")
    has_state  = os.path.exists(state_file) and _state_has_resources(state_file)

    if has_state:
        names = _get_resource_names(state_file)
        n     = _get_resource_count(state_file)
        print(f"  {BRT}{Fore.RED}Resources that will be PERMANENTLY destroyed ({n}):{RST}\n")
        for name in names[:20]: print(f"    {Fore.RED}-{RST}  {name}")
        if len(names) > 20: print(f"    ... and {len(names)-20} more")
        print()
    else:
        warn("No state file — infrastructure may not be deployed.")
        if not confirm("Continue anyway?", default=False):
            info("Cancelled."); return

    print(f"  {BRT}{Fore.RED}{'!'*55}{RST}")
    print(f"  {BRT}{Fore.RED}  WARNING: PERMANENT DELETION — cannot be undone{RST}")
    print(f"  {BRT}{Fore.RED}{'!'*55}{RST}\n")

    if not confirm("Are you sure?", default=False):
        info("Cancelled."); return

    try:
        typed = input(f"  {BRT}{Fore.RED}Type 'yes' to confirm destruction > {RST}").strip().lower()
    except (KeyboardInterrupt, EOFError):
        info("Cancelled."); return

    if typed != "yes":
        warn(f"Typed '{typed}' — cancelled."); return

    env = {**os.environ, **session.env_vars}
    try:
        working(f"{tool} init...")
        r = subprocess.run([tool,"init","-input=false"], cwd=output_dir, env=env,
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            error("init failed:"); print(f"  {Fore.RED}{r.stderr[-1500:]}{RST}"); return
        ok("Init complete")

        working(f"{tool} plan -destroy...")
        r = subprocess.run([tool,"plan","-destroy","-input=false","-out=destroy.tfplan"],
                           cwd=output_dir, env=env, capture_output=True, text=True, timeout=300)
        if r.stdout:
            for line in r.stdout.splitlines()[-25:]:
                col = Fore.RED if line.strip().startswith("- ") else DIM
                print(f"  {col}{line}{RST}")
        if r.returncode != 0:
            error("destroy plan failed:"); print(f"  {Fore.RED}{r.stderr[-1500:]}{RST}"); return

        if not confirm("Execute destruction now?", default=False):
            info("Cancelled after plan."); return

        working("Destroying...")
        r = subprocess.run([tool,"apply","-destroy","-auto-approve","destroy.tfplan"],
                           cwd=output_dir, env=env, capture_output=True, text=True, timeout=900)
        if r.stdout:
            for line in r.stdout.splitlines():
                col = Fore.RED if "Destroying" in line or "destroyed" in line.lower() else DIM
                print(f"  {col}{line}{RST}")

        if r.returncode == 0:
            ok("Infrastructure destroyed.")
            _write_audit_log(output_dir, session, {}, "destroyed")
            if confirm("Delete local output directory too?", default=False):
                shutil.rmtree(output_dir)
                ok(f"Deleted: {output_dir}")
        else:
            error("Destroy failed:"); print(f"  {Fore.RED}{r.stderr[-2000:]}{RST}")

    except subprocess.TimeoutExpired:
        error("Timed out.")
    except Exception as e:
        error(f"Unexpected: {e}")


# ─── Manual command helpers ───────────────────────────────────────────────────

def _print_manual_deploy_commands(output_dir, session):
    tool  = session.iac_tool
    lines = [f"cd {output_dir}", ""]
    if session.env_vars:
        for k, v in session.env_vars.items():
            lines.append(f"export {k}='{v[:4]}****'")
        lines.append("")
    lines += [f"{tool} init", f"{tool} plan", f"{tool} apply"]
    code_block("Manual Deploy", lines)


def _print_manual_destroy_commands(output_dir, session):
    tool  = session.iac_tool
    lines = [f"cd {output_dir}", "",
             f"{tool} init",
             f"{tool} plan -destroy",
             f"{tool} apply -destroy -auto-approve"]
    code_block("Manual Destroy", lines)


def _print_prompt_examples(cloud):
    examples = {
        "aws":   ["make 1 private ec2 instance in mumbai",
                  "create production vpc with 2 subnets"],
        "gcp":   ["create private vpc with 1 e2-micro in mumbai"],
        "azure": ["create secure vnet with 1 private vm"],
    }
    print(f"  {BRT}{Fore.YELLOW}Examples:{RST}")
    for ex in examples.get(cloud, []):
        print(f"    {DIM}>{RST}  {ex}")
    print()


# ─── Audit log ───────────────────────────────────────────────────────────────

def _write_audit_log(output_dir, session, intent, action):
    try:
        os.makedirs("./logs", exist_ok=True)
        entry = {
            "timestamp":  datetime.datetime.utcnow().isoformat(),
            "action":     action,
            "cloud":      session.cloud,
            "region":     session.region,
            "output_dir": output_dir,
            "intent_hash": hashlib.sha256(json.dumps(intent, default=str).encode()).hexdigest(),
        }
        with open("./logs/audit.jsonl","a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def _print_goodbye():
    print(f"\n  {BRT}{Fore.CYAN}╔{'═'*48}╗{RST}")
    print(f"  {BRT}{Fore.CYAN}║{RST}  {Fore.GREEN}Thanks for using Local AI DevSecOps Agent!{Fore.CYAN}  ║{RST}")
    print(f"  {BRT}{Fore.CYAN}║{RST}  {DIM}All credentials cleared from memory.{RST}{Fore.CYAN}        ║{RST}")
    print(f"  {BRT}{Fore.CYAN}╚{'═'*48}╝{RST}\n")
