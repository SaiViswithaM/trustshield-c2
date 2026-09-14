from typing import Any


def convert_analysis_to_evidence(
    analysis_result: dict[str, Any]
) -> dict[str, Any]:
    """
    Convert Member 2 analysis output into the
    evidence format expected by Member 1.
    """

    findings = []

    # -------------------------------------------------
    # 1. Static analysis findings
    # -------------------------------------------------

    for finding in analysis_result.get(
        "static_findings",
        []
    ):
        findings.append({
            "source": "static_analysis",
            "type": finding.get(
                "vulnerability",
                "unknown"
            ),
            "severity": finding.get(
                "severity",
                "UNKNOWN"
            ),
            "confidence": finding.get(
                "confidence",
                0.0
            ),
            "location": (
                f"{finding.get('file', 'unknown')}:"
                f"{finding.get('line', 'unknown')}"
            ),
            "evidence": finding.get(
                "evidence",
                ""
            ),
        })

    # -------------------------------------------------
    # 2. Dynamic analysis observations
    # -------------------------------------------------

    for observation in analysis_result.get(
        "dynamic_observations",
        []
    ):
        if observation.get("status") == "SUSPICIOUS":
            findings.append({
                "source": "dynamic_analysis",
                "type": "command_injection",
                "severity": "UNKNOWN",
                "confidence": 0.60,
                "location": analysis_result.get(
                    "target",
                    "unknown"
                ),
                "evidence": (
                    "Suspicious input observed: "
                    f"{observation.get('input_value', '')}"
                ),
            })

    # -------------------------------------------------
    # 3. Fuzzing evidence
    # -------------------------------------------------

    suspicious_fuzz_cases = []

    for case in analysis_result.get(
        "fuzz_cases",
        []
    ):
        category = case.get(
            "category",
            ""
        )

        if category not in {
            "empty",
            "normal",
        }:
            suspicious_fuzz_cases.append(case)

    if suspicious_fuzz_cases:
        findings.append({
            "source": "fuzzing",
            "type": "command_injection",
            "severity": "UNKNOWN",
            "confidence": 0.50,
            "location": analysis_result.get(
                "target",
                "unknown"
            ),
            "evidence": (
                f"{len(suspicious_fuzz_cases)} "
                "suspicious fuzz cases generated; "
                "execution was not performed."
            ),
        })

    # -------------------------------------------------
    # 4. Return Member 1 evidence format
    # -------------------------------------------------

    return {
        "target": analysis_result.get(
            "target"
        ),
        "findings": findings,
    }