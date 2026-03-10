"""
terminal_ui.py
Beautiful terminal UI using only stdlib + colorama.
No external dependencies beyond colorama (already installed).
"""
import os
import sys
import getpass
import textwrap
from colorama import Fore, Back, Style, init

init(autoreset=True)

# ─── Color shortcuts ─────────────────────────────────────────────────────────
R  = Fore.RED
G  = Fore.GREEN
Y  = Fore.YELLOW
B  = Fore.BLUE
M  = Fore.MAGENTA
C  = Fore.CYAN
W  = Fore.WHITE
DIM = Style.DIM
BRT = Style.BRIGHT
RST = Style.RESET_ALL

# ─── Terminal width ───────────────────────────────────────────────────────────
def term_width():
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 80

def line(char="─", color=Fore.CYAN):
    return color + char * term_width() + RST

def dline(color=Fore.CYAN):
    return color + "═" * term_width() + RST

# ─── Banner ───────────────────────────────────────────────────────────────────
BANNER = r"""
  ██████╗ ███████╗██╗   ██╗███████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
  ██╔══██╗██╔════╝██║   ██║██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
  ██║  ██║█████╗  ██║   ██║███████╗█████╗  ██║     ██║   ██║██████╔╝███████╗
  ██║  ██║██╔══╝  ╚██╗ ██╔╝╚════██║██╔══╝  ██║     ██║   ██║██╔═══╝ ╚════██║
  ██████╔╝███████╗ ╚████╔╝ ███████║███████╗╚██████╗╚██████╔╝██║     ███████║
  ╚═════╝ ╚══════╝  ╚═══╝  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
"""

SUBTITLE = "  🛡  Local AI DevSecOps Agent  ·  All credentials stay on your machine  🛡"

def print_banner():
    w = term_width()
    print()
    print(dline(Fore.CYAN))
    for line_text in BANNER.splitlines():
        print(BRT + Fore.CYAN + line_text)
    print()
    pad = max(0, (w - len(SUBTITLE)) // 2) * " "
    print(BRT + Fore.GREEN + pad + SUBTITLE)
    print()
    print(dline(Fore.CYAN))
    print()

# ─── Section headers ─────────────────────────────────────────────────────────
def section(title, icon="▶"):
    w = term_width()
    bar = "─" * w
    print()
    print(BRT + Fore.CYAN + bar)
    label = f"  {icon}  {title}"
    print(BRT + Fore.WHITE + Back.BLUE + label + " " * (w - len(label)) + RST)
    print(BRT + Fore.CYAN + bar)
    print()

def step(num, title):
    print(f"\n{BRT}{Fore.CYAN}  STEP {num}  {RST}{BRT}{Fore.WHITE}{title}{RST}\n")

# ─── Status messages ─────────────────────────────────────────────────────────
def info(msg):    print(f"  {Fore.CYAN}ℹ{RST}  {msg}")
def ok(msg):      print(f"  {Fore.GREEN}✓{RST}  {BRT}{Fore.GREEN}{msg}{RST}")
def warn(msg):    print(f"  {Fore.YELLOW}⚠{RST}  {Fore.YELLOW}{msg}{RST}")
def error(msg):   print(f"  {Fore.RED}✗{RST}  {BRT}{Fore.RED}{msg}{RST}")
def working(msg): print(f"  {Fore.MAGENTA}⟳{RST}  {Fore.MAGENTA}{msg}{RST}", flush=True)

def badge(label, value, color=Fore.CYAN):
    return f"{DIM}[{RST}{BRT}{color}{label}{RST}{DIM}]{RST} {value}"

def key_value(key, value, key_color=Fore.CYAN, val_color=Fore.WHITE):
    return f"  {BRT}{key_color}{key:<22}{RST} {val_color}{value}{RST}"

# ─── Choice menus ────────────────────────────────────────────────────────────
def choice_menu(title, options, icon="◈"):
    """
    Display a numbered menu and return (index, value).
    options = list of (label, description, extra_info)  OR  list of strings
    """
    print(f"\n  {BRT}{Fore.YELLOW}{icon} {title}{RST}\n")
    for i, opt in enumerate(options, 1):
        if isinstance(opt, tuple):
            label, desc, *extra = opt
            extra_str = f"  {DIM}{extra[0]}{RST}" if extra else ""
            print(f"    {BRT}{Fore.CYAN}[{i}]{RST}  {BRT}{Fore.WHITE}{label:<12}{RST}  "
                  f"{Fore.WHITE}{DIM}{desc}{RST}{extra_str}")
        else:
            print(f"    {BRT}{Fore.CYAN}[{i}]{RST}  {BRT}{Fore.WHITE}{opt}{RST}")
    print()
    while True:
        try:
            raw = input(f"  {BRT}{Fore.GREEN}Enter choice [1-{len(options)}]: {RST}").strip()
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                selected = options[idx]
                label = selected[0] if isinstance(selected, tuple) else selected
                ok(f"Selected: {label}")
                print()
                return idx, selected
            else:
                warn(f"Please enter a number between 1 and {len(options)}")
        except (ValueError, KeyboardInterrupt):
            if isinstance(sys.exc_info()[1], KeyboardInterrupt):
                print()
                abort()
            warn("Invalid input — enter a number")

def abort():
    print(f"\n  {Fore.YELLOW}Aborted.{RST}\n")
    sys.exit(0)

# ─── Secret input ─────────────────────────────────────────────────────────────
def secret_input(prompt_text):
    """Masked input for secrets/passwords."""
    try:
        val = getpass.getpass(f"  {BRT}{Fore.YELLOW}🔑 {prompt_text}: {RST}")
        if val:
            masked = val[:4] + "*" * (len(val) - 4) if len(val) > 4 else "****"
            ok(f"Secret captured  {DIM}({masked}){RST}")
        return val
    except KeyboardInterrupt:
        print()
        abort()

def text_input(prompt_text, default=None, secret=False):
    """Regular text input with optional default."""
    if secret:
        return secret_input(prompt_text)
    default_hint = f" {DIM}[{default}]{RST}" if default else ""
    try:
        val = input(f"  {BRT}{Fore.GREEN}► {prompt_text}{default_hint}: {RST}").strip()
        if not val and default:
            val = default
            info(f"Using default: {default}")
        return val
    except KeyboardInterrupt:
        print()
        abort()

def confirm(msg, default=True):
    """Yes/No confirmation."""
    hint = "Y/n" if default else "y/N"
    try:
        ans = input(f"\n  {BRT}{Fore.YELLOW}? {msg} [{hint}]: {RST}").strip().lower()
        if not ans:
            return default
        return ans in ("y", "yes")
    except KeyboardInterrupt:
        print()
        abort()

# ─── Progress / scanning display ─────────────────────────────────────────────
def scanning_block(title, items):
    """Show a list of scan items with results."""
    print(f"\n  {BRT}{Fore.CYAN}┌─ {title}{RST}")
    for label, result, passed in items:
        icon = f"{Fore.GREEN}✓" if passed else f"{Fore.RED}✗"
        col  = Fore.GREEN if passed else Fore.RED
        print(f"  {BRT}{Fore.CYAN}│{RST}  {icon}{RST}  {label:<35} {col}{result}{RST}")
    print(f"  {BRT}{Fore.CYAN}└{'─'*50}{RST}\n")

def findings_table(findings):
    """Render a security findings table."""
    if not findings:
        ok("No security findings — all checks passed!")
        return
    SEV_COLOR = {"CRITICAL": Fore.RED, "HIGH": Fore.YELLOW,
                 "MEDIUM": Fore.CYAN,  "LOW": Fore.WHITE}
    w = term_width()
    print(f"\n  {BRT}{Fore.WHITE}{'SEVERITY':<12}{'RULE':<35}{'DESCRIPTION'}{RST}")
    print(f"  {'─'*(w-4)}")
    for f in findings:
        sev = f.get("severity","LOW")
        col = SEV_COLOR.get(sev, Fore.WHITE)
        rule = f.get("rule","")[:33]
        desc = f.get("description","")[:w-52]
        print(f"  {BRT}{col}{sev:<12}{RST}{rule:<35}{desc}")
    print()

def code_block(title, code_lines):
    """Display a code snippet in a styled box."""
    w = term_width() - 4
    print(f"\n  {BRT}{Fore.CYAN}╭─ {title} {'─'*(w - len(title) - 3)}╮{RST}")
    for l in code_lines:
        truncated = l[:w-2]
        print(f"  {Fore.CYAN}│{RST} {Fore.GREEN}{DIM}{truncated:<{w-2}}{RST} {Fore.CYAN}│{RST}")
    print(f"  {BRT}{Fore.CYAN}╰{'─'*w}╯{RST}\n")

def summary_box(title, items):
    """Key-value summary box."""
    w = max(60, max(len(k) + len(str(v)) + 8 for k, v in items) + 4)
    border = "─" * w
    print(f"\n  {BRT}{Fore.CYAN}┌{border}┐{RST}")
    pad = (w - len(title) - 2) // 2
    print(f"  {BRT}{Fore.CYAN}│{' '*pad} {Fore.WHITE}{title}{Fore.CYAN}{' '*(w-pad-len(title)-1)}│{RST}")
    print(f"  {BRT}{Fore.CYAN}├{border}┤{RST}")
    for k, v in items:
        line_str = f"  {k}: {v}"
        print(f"  {BRT}{Fore.CYAN}│{RST}  {Fore.YELLOW}{k:<25}{RST}{Fore.WHITE}{str(v):<{w-28}}{Fore.CYAN}│{RST}")
    print(f"  {BRT}{Fore.CYAN}└{border}┘{RST}\n")
