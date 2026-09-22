from typing import Any


def convert_reasoning_to_remediation(
    reasoning_result: dict[str, Any]
) -> dict[str, Any]:
    """
    Convert Member 1 Cyber Reasoner output into the
    remediation input format expected by Member 3.
    """

    return {
        "vulnerability": reasoning_result.get(
            "vulnerability",
            "unknown"
        ),
        "root_cause": reasoning_result.get(
            "root_cause",
            ""
        ),
        "affected_location": reasoning_result.get(
            "affected_location",
            ""
        ),
        "recommended_remediation": reasoning_result.get(
            "remediation",
            ""
        ),
        "verification_requirements": reasoning_result.get(
            "verification_requirements",
            []
        ),
    }