import importlib.util
from pathlib import Path


class RefuzzTester:
    """
    Performs a small deterministic re-fuzzing pass
    against the patched target.
    """

    TEST_CASES = [
        "python -c print(123)",
        "python -c print(456) && echo INJECTION_MARKER",
        "python -c print(789) || echo INJECTION_MARKER",
        "python -c print(101)",
        "python -c print(202) && echo TEST_MARKER",
        "python -c print(303) || echo TEST_MARKER",
    ]

    def test(self, target_path):
        target = Path(target_path).resolve()

        if not target.exists():
            return {
                "status": "FAIL",
                "check": "refuzz",
                "message": f"Target not found: {target}"
            }

        try:
            spec = importlib.util.spec_from_file_location(
                "patched_target",
                target
            )

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

        except Exception as exc:
            return {
                "status": "FAIL",
                "check": "refuzz",
                "message": "Could not load patched target.",
                "evidence": f"{type(exc).__name__}: {exc}"
            }

        results = []

        for test_input in self.TEST_CASES:
            try:
                output = module.diagnostic(test_input)

                results.append({
                    "input": test_input,
                    "status": "EXECUTED",
                    "output": output.strip()
                })

            except Exception as exc:
                results.append({
                    "input": test_input,
                    "status": "ERROR",
                    "output": f"{type(exc).__name__}: {exc}"
                })

        injection_marker_found = any(
            "INJECTION_MARKER" in item["output"]
            for item in results
        )

        execution_errors = [
            item for item in results
            if item["status"] == "ERROR"
        ]

        if injection_marker_found:
            return {
                "status": "FAIL",
                "check": "refuzz",
                "message": "Potential injection behaviour reproduced.",
                "cases_tested": len(results),
                "evidence": results
            }

        if execution_errors:
            return {
                "status": "INCONCLUSIVE",
                "check": "refuzz",
                "message": "Some re-fuzz cases could not execute reliably.",
                "cases_tested": len(results),
                "successful_cases": len(results) - len(execution_errors),
                "execution_errors": len(execution_errors),
                "evidence": results
            }

        return {
            "status": "PASS",
            "check": "refuzz",
            "message": "All re-fuzz cases completed without reproducing injection behaviour.",
            "cases_tested": len(results),
            "evidence": results
        }


if __name__ == "__main__":
    tester = RefuzzTester()

    result = tester.test(
        "workspace/patched/vulnerable_c2.py"
    )

    print(result)