import ast
from pathlib import Path


class PatchValidator:
    """
    Performs basic validation of a patched Python source file.
    """

    def validate_syntax(self, file_path):
        path = Path(file_path)

        if not path.exists():
            return {
                "status": "FAIL",
                "reason": f"File not found: {path}"
            }

        try:
            source = path.read_text(encoding="utf-8")
            ast.parse(source)

            return {
                "status": "PASS",
                "check": "syntax",
                "file": str(path),
                "message": "Python syntax is valid."
            }

        except SyntaxError as exc:
            return {
                "status": "FAIL",
                "check": "syntax",
                "file": str(path),
                "message": str(exc)
            }


if __name__ == "__main__":
    validator = PatchValidator()

    result = validator.validate_syntax(
        "workspace/patched/vulnerable_c2.py"
    )

    print(result)