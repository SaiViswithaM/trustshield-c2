from typing import Any


def convert_analysis_to_evidence(
    analysis_result: dict[str, Any]
) -> dict[str, Any]:
    """
    Convert Member 2 analysis output into the
    evidence format expected by Member 1.
    """

    findings = []

    target = analysis_result.get(
        "target",
        "unknown"
    )

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

    dynamic_observations = analysis_result.get(
        "dynamic_observations",
        []
    )

    for observation in dynamic_observations:

        if observation.get("status") == "SUSPICIOUS":

            findings.append({
                "source": "dynamic_analysis",
                "type": "command_injection",
                "severity": "UNKNOWN",
                "confidence": 0.60,
                "location": target,
                "evidence": (
                    f"Input: "
                    f"{observation.get('input_value', '')}\n"
                    f"Behavior: "
                    f"{observation.get('behavior', '')}\n"
                    f"Details: "
                    f"{observation.get('details', '')}"
                ),
            })

    # -------------------------------------------------
    # 3. Fuzzing evidence
    # -------------------------------------------------

    fuzz_cases = analysis_result.get(
        "fuzz_cases",
        []
    )

    suspicious_fuzz_cases = []

    for case in fuzz_cases:

        category = case.get(
            "category",
            ""
        )

        if category not in {
            "empty",
            "normal",
        }:
            suspicious_fuzz_cases.append(case)

    # -------------------------------------------------
    # 4. Correlate fuzz cases with runtime observations
    # -------------------------------------------------

    executed_fuzz_cases = []

    for observation in dynamic_observations:

        input_value = observation.get(
            "input_value",
            ""
        )

        if any(
            case.get("input") == input_value
            for case in suspicious_fuzz_cases
        ):
            executed_fuzz_cases.append({
                "input": input_value,
                "status": observation.get(
                    "status",
                    "UNKNOWN"
                ),
                "behavior": observation.get(
                    "behavior",
                    "UNKNOWN"
                ),
                "details": observation.get(
                    "details",
                    ""
                ),
            })

    if suspicious_fuzz_cases:

        findings.append({
            "source": "fuzzing",
            "type": "command_injection",
            "severity": "UNKNOWN",
            "confidence": 0.50,
            "location": target,
            "evidence": {
                "generated_cases": len(
                    suspicious_fuzz_cases
                ),
                "executed_cases": len(
                    executed_fuzz_cases
                ),
                "runtime_results": executed_fuzz_cases,
            },
        })

    # -------------------------------------------------
    # 5. Return Member 1 evidence format
    # -------------------------------------------------

    return {
        "target": target,
        "findings": findings,
    }