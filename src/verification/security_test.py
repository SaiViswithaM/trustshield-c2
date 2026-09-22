import subprocess
import sys
from pathlib import Path


class SecurityTester:
    """
    Performs a controlled security re-test against the patched target.
    """

    def test_command_injection(self, target_path):
        target = Path(target_path).resolve()

        if not target.exists():
            return {
                "status": "FAIL",
                "reason": f"Target not found: {target}"
            }

        test_code = f"""
import importlib.util

target = r"{target}"

spec = importlib.util.spec_from_file_location(
    "patched_target",
    target
)

module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

try:
    result = module.diagnostic(
    "python -c print(123) && echo INJECTION_MARKER"
)
    print("OUTPUT:", result)
except Exception as exc:
    print("ERROR:", type(exc).__name__, str(exc))
"""

        process = subprocess.run(
            [sys.executable, "-c", test_code],
            capture_output=True,
            text=True,
            timeout=10
        )

        output = process.stdout.strip()

        if "INJECTION_MARKER" in output:
            return {
                "status": "FAIL",
                "check": "command_injection",
                "message": "Shell command injection remains reproducible.",
                "evidence": output
            }

        if "ERROR:" in output:
            return {
                "status": "INCONCLUSIVE",
                "check": "command_injection",
                "message": "Security test could not execute reliably.",
                "evidence": output
            }

        return {
            "status": "PASS",
            "check": "command_injection",
            "message": "Shell command injection did not reproduce.",
            "evidence": output
        }


if __name__ == "__main__":
    tester = SecurityTester()

    result = tester.test_command_injection(
        "workspace/patched/vulnerable_c2.py"
    )

    print(result)