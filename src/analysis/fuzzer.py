from dataclasses import dataclass


@dataclass
class FuzzCase:
    input_value: str
    category: str


class SecurityFuzzer:

    def generate_cases(self) -> list[FuzzCase]:
        return [
            FuzzCase("", "empty"),
            FuzzCase("127.0.0.1", "normal"),
            FuzzCase("localhost", "normal"),
            FuzzCase("127.0.0.1;test", "command_separator"),
            FuzzCase("127.0.0.1 && test", "command_chaining"),
            FuzzCase("127.0.0.1 | test", "pipe"),
            FuzzCase("$(test)", "command_substitution"),
            FuzzCase("`test`", "command_substitution"),
        ]