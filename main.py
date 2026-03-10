#!/usr/bin/env python3
"""
main.py — Local AI DevSecOps Agent
Entry point: runs setup wizard then drops into agent prompt loop.

Usage:
    python main.py                  # Full interactive mode
    python main.py --skip-setup     # Skip wizard (use existing session)
    python main.py audit <path>     # Audit-only mode
"""
import sys
import os

# Ensure the project root is in the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent.terminal_ui import print_banner, section, info, ok, warn, error, confirm, Fore, BRT, RST
from agent.setup_wizard import run_setup_wizard
from agent.agent_loop import run_agent_loop


def main():
    args = sys.argv[1:]

    # Audit-only shortcut: python main.py audit ./path
    if len(args) >= 2 and args[0] == "audit":
        _run_audit_mode(args[1])
        return

    print_banner()

    info("This agent runs entirely on your local machine.")
    info("Your credentials are held in memory only and never sent externally.")
    print()

    try:
        session = run_setup_wizard()
        run_agent_loop(session)
    except KeyboardInterrupt:
        print(f"\n\n  {Fore.YELLOW}Interrupted.{RST}\n")
        sys.exit(0)


def _run_audit_mode(path: str):
    """Quick audit mode — no credentials or cloud selection needed."""
    print_banner()
    section("AUDIT MODE", "🔍")
    info(f"Auditing: {path}")

    from agent.security_scanner import run_all_scanners
    from agent.terminal_ui import findings_table
    from agent.setup_wizard import AgentSession

    session = AgentSession(cloud="aws", iac_tool="terraform")
    results = run_all_scanners(path, "aws", "terraform")

    if results["findings"]:
        findings_table(results["findings"])

    c = results["critical"]
    h = results["high"]
    m = results["medium"]
    lo = results["low"]

    print(f"\n  {'─'*50}")
    c_col = Fore.RED if c > 0 else Fore.GREEN
    h_col = Fore.YELLOW if h > 0 else Fore.GREEN
    print(f"  {BRT}{c_col}CRITICAL: {c}  {h_col}HIGH: {h}  {Fore.CYAN}MEDIUM: {m}  {Fore.WHITE}LOW: {lo}{RST}\n")

    sys.exit(1 if c > 0 else 0)


if __name__ == "__main__":
    main()