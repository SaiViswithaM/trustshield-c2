from dataclasses import dataclass
from typing import Any


@dataclass
class DynamicObservation:
    status: str
    input_value: str
    behavior: str
    details: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "input_value": self.input_value,
            "behavior": self.behavior,
            "details": self.details,
        }


class DynamicAnalyzer:

    def analyze_observation(
        self,
        input_value: str,
        behavior: str,
        details: str,
    ) -> DynamicObservation:

        suspicious = any(
            token in input_value
            for token in [";", "&&", "||", "|", "$(", "`"]
        )

        status = "SUSPICIOUS" if suspicious else "NORMAL"

        return DynamicObservation(
            status=status,
            input_value=input_value,
            behavior=behavior,
            details=details,
        )