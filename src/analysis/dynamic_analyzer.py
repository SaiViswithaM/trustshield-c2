from dataclasses import dataclass
from typing import Any
import importlib.util
from pathlib import Path


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
    """
    Controlled runtime analyzer.

    Executes an intentionally vulnerable local test target
    with controlled inputs and records observable behaviour.
    """

    INJECTION_MARKERS = [
        "INJECTION_MARKER",
        "TEST_MARKER",
    ]

    def analyze_observation(
        self,
        target_path: str,
        input_value: str,
    ) -> DynamicObservation:

        target = Path(target_path).resolve()

        if not target.exists():
            return DynamicObservation(
                status="ERROR",
                input_value=input_value,
                behavior="not_executed",
                details=f"Target not found: {target}",
            )

        try:
            spec = importlib.util.spec_from_file_location(
                "dynamic_target",
                target,
            )

            if spec is None or spec.loader is None:
                return DynamicObservation(
                    status="ERROR",
                    input_value=input_value,
                    behavior="not_executed",
                    details="Could not load target module.",
                )

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            diagnostic = getattr(module, "diagnostic", None)

            if diagnostic is None:
                return DynamicObservation(
                    status="ERROR",
                    input_value=input_value,
                    behavior="not_executed",
                    details="Target does not expose diagnostic().",
                )

            output = diagnostic(input_value)
            output_text = str(output)

            marker_found = any(
                marker in output_text
                for marker in self.INJECTION_MARKERS
            )

            if marker_found:
                return DynamicObservation(
                    status="SUSPICIOUS",
                    input_value=input_value,
                    behavior="unexpected_command_execution",
                    details=(
                        "Controlled injection marker was observed "
                        f"in runtime output: {output_text!r}"
                    ),
                )

            return DynamicObservation(
                status="EXECUTED",
                input_value=input_value,
                behavior="runtime_observed",
                details=f"Output: {output_text!r}",
            )

        except Exception as exc:
            return DynamicObservation(
                status="ERROR",
                input_value=input_value,
                behavior="runtime_error",
                details=f"{type(exc).__name__}: {exc}",
            )