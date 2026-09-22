import json
from src.verification.run_verification import run_verification
from src.analysis.engine import AnalysisEngine
from src.analysis.reasoning_adapter import convert_analysis_to_evidence
from src.reasoning.reasoner import OpenRouterCyberReasoner
from src.reasoning.remediation_adapter import (
    convert_reasoning_to_remediation,
)
from src.verification.remediation_input import (
    prepare_remediation,
)
from src.verification.patcher import PatchApplier


TARGET = "examples/vulnerable_c2.py"
WORKSPACE = "workspace"


def main():
    print("=" * 60)
    print("TRUSTSHIELD-C2")
    print("Evidence-Driven Autonomous Cyber Reasoning")
    print("=" * 60)

    # -------------------------------------------------
    # STEP 1 — FIND
    # -------------------------------------------------

    print("\n[1/5] FIND — Security Analysis")

    analysis_engine = AnalysisEngine()

    analysis_result = analysis_engine.analyze(
        TARGET
    )

    evidence = convert_analysis_to_evidence(
        analysis_result
    )

    print(f"Target: {TARGET}")
    print(
        f"Evidence findings: "
        f"{len(evidence['findings'])}"
    )

    # -------------------------------------------------
    # STEP 2 — UNDERSTAND
    # -------------------------------------------------

    print("\n[2/5] UNDERSTAND — Cyber Reasoner")

    reasoner = OpenRouterCyberReasoner()

    reasoning_result = reasoner.analyse(
        evidence
    )

    print(
        f"Vulnerability: "
        f"{reasoning_result['vulnerability']}"
    )

    print(
        f"Severity: "
        f"{reasoning_result['severity']}"
    )

    print(
        f"Confidence: "
        f"{reasoning_result['confidence']}"
    )

    print(
        f"Location: "
        f"{reasoning_result['affected_location']}"
    )

    # -------------------------------------------------
    # STEP 3 — FIX PREPARATION
    # -------------------------------------------------

    print("\n[3/5] FIX — Remediation Preparation")

    remediation = convert_reasoning_to_remediation(
        reasoning_result
    )

    prepared = prepare_remediation(
        remediation
    )

    print(
        f"Status: "
        f"{prepared['status']}"
    )

    print(
        f"Recommended remediation: "
        f"{prepared['recommended_remediation']}"
    )

    # -------------------------------------------------
    # STEP 4 — PATCH
    # -------------------------------------------------

    print("\n[4/5] FIX — Patch Application")

    patcher = PatchApplier()

    workspace_result = patcher.prepare_patch(
        remediation=prepared,
        target_path=TARGET,
        workspace_path=WORKSPACE,
    )

    patch_result = (
        patcher.apply_command_injection_patch(
            workspace_result["patched"]
        )
    )

    print(
        f"Patch status: "
        f"{patch_result['patch_status']}"
    )

    print(
        f"Patched file: "
        f"{patch_result['patched_file']}"
    )

    # -------------------------------------------------
    # STEP 5 — PROVE
    # -------------------------------------------------

    print("\n[5/5] PROVE — Independent Verification")

    verification_report = run_verification()

    print(
        f"Verification: "
        f"{verification_report['verification']}"
    )

    print(
        f"Verified: "
        f"{verification_report['verified']}"
    )

    # -------------------------------------------------
    # SUMMARY
    # -------------------------------------------------

    print("\n" + "=" * 60)
    print("TRUSTSHIELD-C2 PIPELINE")
    print("=" * 60)

    print("FIND       : COMPLETE")
    print("UNDERSTAND : COMPLETE")
    print("FIX        : COMPLETE")
    print("PROVE      : COMPLETE")

    if verification_report["verified"]:
        print("VERIFIED   : YES")
    else:
        print("VERIFIED   : NO")
    print("=" * 60)


if __name__ == "__main__":
    main()