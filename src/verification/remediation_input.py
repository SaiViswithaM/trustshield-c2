from typing import Any


def validate_remediation_input(
    remediation: dict[str, Any]
) -> None:
    """
    Validate the remediation contract received from
    Member 1 before Member 3 acts on it.
    """

    required_fields = [
        "vulnerability",
        "root_cause",
        "affected_location",
        "recommended_remediation",
        "verification_requirements",
    ]

    missing_fields = [
        field
        for field in required_fields
        if field not in remediation
    ]

    if missing_fields:
        raise ValueError(
            f"Missing remediation fields: {missing_fields}"
        )

    if not remediation["vulnerability"]:
        raise ValueError(
            "Remediation vulnerability is empty."
        )

    if not remediation["recommended_remediation"]:
        raise ValueError(
            "Recommended remediation is empty."
        )

    if not isinstance(
        remediation["verification_requirements"],
        list
    ):
        raise ValueError(
            "verification_requirements must be a list."
        )


def prepare_remediation(
    remediation: dict[str, Any]
) -> dict[str, Any]:
    """
    Validate and prepare Member 1's remediation
    for Member 3.
    """

    validate_remediation_input(remediation)

    return {
        "vulnerability": remediation["vulnerability"],
        "root_cause": remediation["root_cause"],
        "affected_location": remediation["affected_location"],
        "recommended_remediation": remediation[
            "recommended_remediation"
        ],
        "verification_requirements": remediation[
            "verification_requirements"
        ],
        "status": "READY_FOR_REMEDIATION",
    }