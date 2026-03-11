"""
iac_patcher.py
Patch / modify existing generated IaC code in-place.

Three use cases:
  1. Fix vulnerabilities found by scanner → auto-patch based on finding rules
  2. User-driven modification before deploy → rewrite sections per prompt
  3. Modify live infra → patch + terraform apply (incremental update)

The patcher works entirely on the raw .tf files in an output directory.
It never regenerates from scratch — it surgically edits the existing code,
preserving terraform state compatibility.
"""
import os
import re
import shutil
import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict


@dataclass
class PatchResult:
    success: bool
    patched_files: List[str] = field(default_factory=list)
    changes: List[str] = field(default_factory=list)   # human-readable change log
    error: str = ""


# ─── Vulnerability auto-fix rules ────────────────────────────────────────────
#
# Each rule maps a scanner finding (by rule ID or description keyword) to a
# deterministic sed-style replacement in the Terraform code.
#
# Format: (match_keywords, pattern, replacement, description)
# match_keywords: list of strings — if ANY appear in finding rule/description, apply this fix
# pattern:        regex to find in the .tf file
# replacement:    what to replace with
# description:    human-readable change summary

VULN_FIX_RULES = [
    # ── Encryption ────────────────────────────────────────────────────────────
    (
        ["encrypted", "encryption", "encrypt"],
        r'encrypted\s*=\s*false',
        'encrypted = true',
        "Enabled encryption (was: false)"
    ),
    (
        ["publicly_accessible", "public access", "public_access"],
        r'publicly_accessible\s*=\s*true',
        'publicly_accessible = false',
        "Disabled public accessibility"
    ),
    # ── IMDSv2 ────────────────────────────────────────────────────────────────
    (
        ["imds", "metadata", "http_tokens", "imdsv2"],
        r'http_tokens\s*=\s*"optional"',
        'http_tokens = "required"',
        "Enforced IMDSv2 (http_tokens = required)"
    ),
    # ── Skip final snapshot ───────────────────────────────────────────────────
    (
        ["snapshot", "final_snapshot", "skip_final"],
        r'skip_final_snapshot\s*=\s*true',
        'skip_final_snapshot = false',
        "Enabled final snapshot on DB deletion"
    ),
    # ── Deletion protection ───────────────────────────────────────────────────
    (
        ["deletion_protection", "deletion protection"],
        r'deletion_protection\s*=\s*false',
        'deletion_protection = true',
        "Enabled deletion protection"
    ),
    # ── Multi-AZ ──────────────────────────────────────────────────────────────
    (
        ["multi_az", "multi az", "availability"],
        r'multi_az\s*=\s*false',
        'multi_az = true',
        "Enabled Multi-AZ for high availability"
    ),
    # ── Key rotation ──────────────────────────────────────────────────────────
    (
        ["key_rotation", "key rotation", "rotate"],
        r'enable_key_rotation\s*=\s*false',
        'enable_key_rotation = true',
        "Enabled KMS key rotation"
    ),
    # ── EBS optimization ─────────────────────────────────────────────────────
    (
        ["ebs_optimized", "ebs optimized"],
        r'ebs_optimized\s*=\s*false',
        'ebs_optimized = true',
        "Enabled EBS optimization"
    ),
    # ── Versioning ────────────────────────────────────────────────────────────
    (
        ["versioning", "version"],
        r'(versioning\s*\{[^}]*enabled\s*=\s*)false',
        r'\1true',
        "Enabled S3 versioning"
    ),
    # ── Public IP on EC2 ─────────────────────────────────────────────────────
    (
        ["public_ip", "public ip", "associate_public"],
        r'associate_public_ip_address\s*=\s*true',
        'associate_public_ip_address = false',
        "Disabled public IP assignment on EC2 instance"
    ),
    # ── S3 ACL ────────────────────────────────────────────────────────────────
    (
        ["acl", "public-read", "public_acl"],
        r'acl\s*=\s*"public-read[^"]*"',
        'acl = "private"',
        "Changed S3 ACL from public-read to private"
    ),
    # ── VPC flow logs ─────────────────────────────────────────────────────────
    (
        ["flow_log", "flow log", "vpc flow"],
        None,   # additive fix — handled separately
        None,
        "VPC flow logs — requires additive block (use 'fix flow logs' prompt)"
    ),
    # ── SSL/TLS ───────────────────────────────────────────────────────────────
    (
        ["ssl", "tls", "transit_encryption", "in_transit"],
        r'transit_encryption_enabled\s*=\s*false',
        'transit_encryption_enabled = true',
        "Enabled in-transit encryption"
    ),
    (
        ["at_rest", "at-rest", "rest_encryption"],
        r'at_rest_encryption_enabled\s*=\s*false',
        'at_rest_encryption_enabled = true',
        "Enabled at-rest encryption"
    ),
]


# ─── Prompt-driven patch rules ────────────────────────────────────────────────
#
# These handle free-text modification prompts like:
#   "change instance type to t3.large"
#   "increase storage to 100gb"
#   "add another subnet"
#   "change region to us-east-1"
#   "increase instance count to 3"

PROMPT_PATCH_RULES = [
    # Instance type change
    (
        r'(?:change|use|switch|update)\s+instance\s+type\s+to\s+([\w.]+)',
        lambda m, code: re.sub(
            r'(instance_type\s*=\s*")[^"]*(")',
            lambda x: f'{x.group(1)}{m.group(1)}{x.group(2)}',
            code
        ),
        lambda m: f"Changed instance_type to {m.group(1)}"
    ),
    # Storage size change
    (
        r'(?:increase|change|set|resize)\s+(?:storage|disk|volume|ebs)\s+(?:to\s+)?(\d+)\s*(?:gb|g)?',
        lambda m, code: re.sub(
            r'(volume_size\s*=\s*)\d+',
            lambda x: f'{x.group(1)}{m.group(1)}',
            code
        ),
        lambda m: f"Changed volume_size to {m.group(1)} GB"
    ),
    # Instance count change
    (
        r'(?:change|set|increase|scale)\s+(?:instance\s+)?count\s+to\s+(\d+)',
        lambda m, code: re.sub(
            r'(count\s*=\s*)\d+',
            lambda x: f'{x.group(1)}{m.group(1)}',
            code
        ),
        lambda m: f"Changed instance count to {m.group(1)}"
    ),
    # Region change
    (
        r'(?:change|move|switch)\s+region\s+to\s+([\w-]+)',
        lambda m, code: re.sub(
            r'(region\s*=\s*")[^"]*(")',
            lambda x: f'{x.group(1)}{m.group(1)}{x.group(2)}',
            code
        ),
        lambda m: f"Changed region to {m.group(1)}"
    ),
    # Retention days
    (
        r'(?:set|change|update)\s+retention\s+(?:to\s+)?(\d+)\s*days?',
        lambda m, code: re.sub(
            r'(retention_in_days\s*=\s*)\d+',
            lambda x: f'{x.group(1)}{m.group(1)}',
            code
        ),
        lambda m: f"Changed log retention to {m.group(1)} days"
    ),
    # Enable versioning
    (
        r'enable\s+versioning',
        lambda m, code: re.sub(
            r'(versioning\s*\{[^}]*enabled\s*=\s*)false',
            r'\1true',
            code
        ),
        lambda m: "Enabled S3 versioning"
    ),
    # Disable public access
    (
        r'(?:disable|remove|block)\s+public\s+(?:access|ip)',
        lambda m, code: re.sub(
            r'associate_public_ip_address\s*=\s*true',
            'associate_public_ip_address = false',
            re.sub(r'publicly_accessible\s*=\s*true', 'publicly_accessible = false', code)
        ),
        lambda m: "Disabled public access/IP"
    ),
    # Enable encryption
    (
        r'enable\s+encryption',
        lambda m, code: re.sub(
            r'encrypted\s*=\s*false',
            'encrypted = true',
            code
        ),
        lambda m: "Enabled encryption"
    ),
    # Enable deletion protection
    (
        r'enable\s+deletion\s+protection',
        lambda m, code: re.sub(
            r'deletion_protection\s*=\s*false',
            'deletion_protection = true',
            code
        ),
        lambda m: "Enabled deletion protection"
    ),
    # VM/machine size (GCP)
    (
        r'(?:change|use|switch)\s+machine\s+type\s+to\s+([\w-]+)',
        lambda m, code: re.sub(
            r'(machine_type\s*=\s*")[^"]*(")',
            lambda x: f'{x.group(1)}{m.group(1)}{x.group(2)}',
            code
        ),
        lambda m: f"Changed machine_type to {m.group(1)}"
    ),
    # VM size (Azure)
    (
        r'(?:change|use|switch)\s+vm\s+size\s+to\s+([\w_]+)',
        lambda m, code: re.sub(
            r'(vm_size\s*=\s*")[^"]*(")',
            lambda x: f'{x.group(1)}{m.group(1)}{x.group(2)}',
            code
        ),
        lambda m: f"Changed vm_size to {m.group(1)}"
    ),
    # CIDR block change
    (
        r'(?:change|set|use)\s+cidr\s+(?:to\s+)?([\d./]+)',
        lambda m, code: re.sub(
            r'(cidr_block\s*=\s*")[^"]*(")',
            lambda x: f'{x.group(1)}{m.group(1)}{x.group(2)}',
            code
        ),
        lambda m: f"Changed CIDR to {m.group(1)}"
    ),
    # Key rotation
    (
        r'enable\s+key\s+rotation',
        lambda m, code: re.sub(
            r'enable_key_rotation\s*=\s*false',
            'enable_key_rotation = true',
            code
        ),
        lambda m: "Enabled KMS key rotation"
    ),
]


class IaCPatcher:
    """
    Patches existing Terraform files in an output directory.
    Supports:
      - Auto-fix from scanner findings
      - Prompt-driven modification
      - Both before and after deployment (state-safe edits)
    """

    def __init__(self):
        pass

    # ─── Public API ──────────────────────────────────────────────────────────

    def fix_vulnerabilities(self, output_dir: str, findings: List[dict]) -> PatchResult:
        """
        Auto-fix vulnerabilities found by the security scanner.
        Applies all matching fix rules for each finding.
        """
        if not findings:
            return PatchResult(success=True, changes=["No findings to fix"])

        tf_files = self._get_tf_files(output_dir)
        if not tf_files:
            return PatchResult(success=False, error=f"No .tf files found in {output_dir}")

        all_changes = []
        patched_files = set()

        for finding in findings:
            rule_id = finding.get("rule", "")
            desc    = finding.get("description", "").lower()
            sev     = finding.get("severity", "")
            search_text = f"{rule_id} {desc}".lower()

            for keywords, pattern, replacement, change_desc in VULN_FIX_RULES:
                if pattern is None:
                    continue  # additive fix — skip for now
                if any(kw in search_text for kw in keywords):
                    for tf_file in tf_files:
                        original = open(tf_file).read()
                        patched  = re.sub(pattern, replacement, original, flags=re.IGNORECASE)
                        if patched != original:
                            self._backup_and_write(tf_file, patched)
                            patched_files.add(tf_file)
                            change = f"[{sev}] {change_desc}  (in {os.path.basename(tf_file)})"
                            if change not in all_changes:
                                all_changes.append(change)

        if not all_changes:
            return PatchResult(
                success=True,
                changes=["No automatic fixes available for these findings."],
                patched_files=[]
            )

        return PatchResult(
            success=True,
            patched_files=list(patched_files),
            changes=all_changes
        )

    def apply_prompt_patch(self, output_dir: str, prompt: str) -> PatchResult:
        """
        Apply a user-driven modification prompt to existing IaC code.
        e.g. "change instance type to t3.large"
             "increase storage to 100gb"
             "disable public access"
        """
        tf_files = self._get_tf_files(output_dir)
        if not tf_files:
            return PatchResult(success=False, error=f"No .tf files found in {output_dir}")

        p = prompt.lower().strip()
        all_changes = []
        patched_files = set()

        for pattern_str, apply_fn, describe_fn in PROMPT_PATCH_RULES:
            m = re.search(pattern_str, p, re.IGNORECASE)
            if m:
                for tf_file in tf_files:
                    original = open(tf_file).read()
                    try:
                        patched = apply_fn(m, original)
                    except Exception:
                        continue
                    if patched != original:
                        self._backup_and_write(tf_file, patched)
                        patched_files.add(tf_file)
                        all_changes.append(f"{describe_fn(m)}  (in {os.path.basename(tf_file)})")

        if not all_changes:
            return PatchResult(
                success=False,
                error="Could not match your request to a known patch rule.\n"
                      "Try more specific phrasing like:\n"
                      "  'change instance type to t3.large'\n"
                      "  'increase storage to 100gb'\n"
                      "  'disable public access'\n"
                      "  'enable encryption'\n"
                      "  'change instance count to 3'"
            )

        return PatchResult(
            success=True,
            patched_files=list(patched_files),
            changes=all_changes
        )

    def get_diff(self, output_dir: str) -> List[str]:
        """
        Return a simple line-level diff between current .tf files and their backups.
        Shows what changed in a readable format.
        """
        lines = []
        for tf_file in self._get_tf_files(output_dir):
            backup = tf_file + ".bak"
            if not os.path.exists(backup):
                continue
            old_lines = open(backup).readlines()
            new_lines = open(tf_file).readlines()
            file_name = os.path.basename(tf_file)
            file_header_added = False
            for i, (old, new) in enumerate(zip(old_lines, new_lines), 1):
                if old != new:
                    if not file_header_added:
                        lines.append(f"  📄 {file_name}")
                        file_header_added = True
                    lines.append(f"  {i:4d} - {old.rstrip()}")
                    lines.append(f"  {i:4d} + {new.rstrip()}")
        return lines if lines else ["  (no diff available)"]

    def restore_backup(self, output_dir: str) -> bool:
        """Restore all .tf files from their .bak backups (undo last patch)."""
        restored = False
        for tf_file in self._get_tf_files(output_dir):
            backup = tf_file + ".bak"
            if os.path.exists(backup):
                shutil.copy2(backup, tf_file)
                restored = True
        return restored

    # ─── Internal helpers ─────────────────────────────────────────────────────

    def _get_tf_files(self, output_dir: str) -> List[str]:
        """Get all .tf files in output_dir, excluding backend.tf (usually safe to edit main.tf only)."""
        return [
            str(p) for p in Path(output_dir).glob("*.tf")
            if p.name not in ("backend.tf",) and p.is_file()
        ]

    def _backup_and_write(self, tf_file: str, new_content: str):
        """Write new content, keeping .bak of the previous version."""
        backup = tf_file + ".bak"
        # Only back up if no backup exists yet for this patch cycle
        # (so we always preserve the pre-patch state, not a mid-patch state)
        if not os.path.exists(backup):
            shutil.copy2(tf_file, backup)
        with open(tf_file, "w") as f:
            f.write(new_content)
