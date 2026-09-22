import importlib.util
from pathlib import Path


class RegressionTester:
    """
    Verifies that legitimate functionality still works
    after security remediation.
    """

    def test_diagnostic_functionality(self, target_path):
        target = Path(target_path).resolve()

        if not target.exists():
            return {
                "status": "FAIL",
                "check": "regression",
                "message": f"Target not found: {target}"
            }

        try:
            spec = importlib.util.spec_from_file_location(
                "patched_target",
                target
            )

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            output = module.diagnostic(
                "python -c print(123)"
            )

            if output.strip() == "123":
                return {
                    "status": "PASS",
                    "check": "regression",
                    "message": "Legitimate diagnostic functionality still works.",
                    "evidence": output.strip()
                }

            return {
                "status": "FAIL",
                "check": "regression",
                "message": "Diagnostic functionality produced unexpected output.",
                "evidence": output.strip()
            }

        except Exception as exc:
            return {
                "status": "FAIL",
                "check": "regression",
                "message": "Regression test failed during execution.",
                "evidence": f"{type(exc).__name__}: {exc}"
            }


if __name__ == "__main__":
    tester = RegressionTester()

    result = tester.test_diagnostic_functionality(
        "workspace/patched/vulnerable_c2.py"
    )

    print(result)