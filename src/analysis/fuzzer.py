from dataclasses import dataclass


@dataclass
class FuzzCase:
    input_value: str
    category: str


class SecurityFuzzer:

    def generate_cases(self) -> list[FuzzCase]:
        marker = "INJECTION_MARKER"

        return [
            FuzzCase("", "empty"),
            FuzzCase("127.0.0.1", "normal"),
            FuzzCase("localhost", "normal"),

            FuzzCase(
                f"python -c print(123) && echo {marker}",
                "command_chaining",
            ),

            FuzzCase(
                f"python -c print(456) || echo {marker}",
                "command_chaining",
            ),

            FuzzCase(
                f"python -c print(789) & echo {marker}",
                "command_chaining",
            ),
        ]