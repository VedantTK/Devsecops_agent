#!/usr/bin/env python3
"""
test_agent.py
Quick smoke test — verifies all modules import and core logic works.
Run: python tests/test_agent.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_imports():
    print("Testing imports...")
    from agent.terminal_ui import print_banner, ok, warn, error, info
    from agent.setup_wizard import AgentSession, run_setup_wizard
    from agent.iac_generator import IaCGenerator, IntentParser
    from agent.security_scanner import run_all_scanners
    from agent.agent_loop import run_agent_loop
    print("  ✓ All imports OK")

def test_intent_parser():
    print("Testing intent parser...")
    from agent.iac_generator import IntentParser
    from agent.setup_wizard import AgentSession

    session = AgentSession(cloud="aws", iac_tool="terraform",
                           region="ap-south-1", compliance_targets=["cis"])
    parser = IntentParser()

    cases = [
        "make secure infra with 1 private instance in mumbai region",
        "create production vpc with 2 private subnets",
        "deploy 3 t3.small instances with encrypted storage",
        "setup kubernetes cluster with network policies",
    ]
    for prompt in cases:
        intent = parser.parse(prompt, session)
        assert intent["instance_count"] >= 0
        assert len(intent["resource_types"]) > 0
        print(f"  ✓ '{prompt[:50]}...' → {intent['resource_types']}")

def test_iac_generation():
    print("Testing IaC generation...")
    from agent.iac_generator import IaCGenerator, IntentParser
    from agent.setup_wizard import AgentSession
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        for cloud in ["aws", "gcp", "azure"]:
            session = AgentSession(
                cloud=cloud, iac_tool="terraform",
                region={"aws": "ap-south-1", "gcp": "asia-south1", "azure": "centralindia"}[cloud],
                compliance_targets=["cis"],
            )
            if cloud == "gcp":
                from agent.setup_wizard import GCPCredentials
                session.credentials = GCPCredentials(project_id="test-project")

            parser = IntentParser()
            intent = parser.parse("create secure private instance", session)

            gen = IaCGenerator(output_base=tmpdir)
            result = gen.generate(intent, session)

            assert result.success, f"Generation failed for {cloud}: {result.error}"
            assert len(result.files) > 0
            # Verify no hardcoded secrets in output
            for fpath in result.files:
                content = open(fpath).read()
                assert "AKIA" not in content, "AWS key leaked into generated code!"
                assert 'password = "' not in content, "Hardcoded password in generated code!"
            print(f"  ✓ {cloud.upper()} Terraform generated — {len(result.files)} files, 0 security issues")

def test_guardrails():
    print("Testing security guardrails...")
    from agent.iac_generator import FORBIDDEN_PATTERNS
    import re

    bad_code = 'encrypted = false\npublicly_accessible = true\npassword = "mysecret123"'
    found = []
    for pattern, severity, msg in FORBIDDEN_PATTERNS:
        if re.search(pattern, bad_code, re.IGNORECASE):
            found.append(severity)

    assert "CRITICAL" in found, "Guardrails should catch CRITICAL issues"
    print(f"  ✓ Guardrails caught {len(found)} issues in bad code sample")

    good_code = 'encrypted = true\npublicly_accessible = false\npassword = var.db_password'
    issues = []
    for pattern, severity, msg in FORBIDDEN_PATTERNS:
        if re.search(pattern, good_code, re.IGNORECASE):
            issues.append(msg)
    assert len(issues) == 0, f"Guardrails false positive on good code: {issues}"
    print("  ✓ No false positives on secure code")

def test_terminal_ui():
    print("Testing terminal UI (no crash)...")
    from agent.terminal_ui import (
        ok, warn, error, info, working,
        code_block, summary_box, scanning_block, findings_table
    )
    ok("test ok")
    warn("test warn")
    error("test error")
    info("test info")
    code_block("test", ["line 1", "line 2"])
    summary_box("Test", [("Key", "Value"), ("Another", "Value2")])
    scanning_block("Scan", [("checkov", "PASS", True), ("tfsec", "FAIL", False)])
    findings_table([{"severity": "HIGH", "rule": "TEST-001", "description": "Test finding"}])
    print("  ✓ All UI components render without errors")

if __name__ == "__main__":
    print("\n🛡 DevSecOps Agent — Smoke Tests\n" + "─"*40)
    tests = [
        test_imports,
        test_terminal_ui,
        test_intent_parser,
        test_iac_generation,
        test_guardrails,
    ]
    passed = failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"  ✗ FAILED: {e}")
            import traceback; traceback.print_exc()
            failed += 1
    print(f"\n{'─'*40}")
    print(f"Results: {passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
