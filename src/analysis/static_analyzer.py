import ast
from pathlib import Path

from .schemas import SecurityFinding


class StaticAnalyzer(ast.NodeVisitor):

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings: list[SecurityFinding] = []

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
                and node.func.attr in {
                    "run",
                    "Popen",
                    "call",
                    "check_call",
                    "check_output",
                }
            ):
                for keyword in node.keywords:
                    if (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ):
                        self.findings.append(
                            SecurityFinding(
                                source="static_analysis",
                                rule="PY001",
                                vulnerability="command_injection",
                                severity="HIGH",
                                confidence=0.95,
                                file=self.file_path,
                                line=node.lineno,
                                evidence="subprocess call uses shell=True",
                                message=(
                                    "Potential command injection: "
                                    "subprocess is executed with shell=True."
                                ),
                            )
                        )

        self.generic_visit(node)


def analyze_file(file_path: str) -> list[SecurityFinding]:
    path = Path(file_path)

    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))

    analyzer = StaticAnalyzer(str(path))
    analyzer.visit(tree)

    return analyzer.findings