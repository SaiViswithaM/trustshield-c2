import json
from datetime import datetime, timezone


class VerificationReport:
    """
    Builds a structured verification report from
    independent verification results.
    """

    def build_report(self, target, results, gate_result):
        return {
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "verification": gate_result["status"],
            "verified": gate_result["verified"],
            "checks": {
                "security_test": results.get(
                    "security_test", {}
                ),
                "regression_test": results.get(
                    "regression_test", {}
                ),
                "refuzz": results.get(
                    "refuzz", {}
                ),
            },
            "failed_checks": gate_result.get(
                "failed_checks", []
            ),
        }

    def save(self, report, output_path):
        with open(
            output_path,
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                report,
                file,
                indent=4
            )

        return output_path


if __name__ == "__main__":
    report_builder = VerificationReport()

    results = {
        "security_test": {
            "status": "PASS",
            "message": "Shell command injection did not reproduce.",
        },
        "regression_test": {
            "status": "PASS",
            "message": "Legitimate diagnostic functionality still works.",
        },
        "refuzz": {
            "status": "PASS",
            "message": (
                "All re-fuzz cases completed without "
                "reproducing injection behaviour."
            ),
        },
    }

    gate_result = {
        "status": "VERIFIED",
        "verified": True,
        "failed_checks": [],
    }

    report = report_builder.build_report(
        "workspace/patched/vulnerable_c2.py",
        results,
        gate_result
    )

    print(json.dumps(report, indent=4))