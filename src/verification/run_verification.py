import json

from src.verification.security_test import SecurityTester
from src.verification.regression_test import RegressionTester
from src.verification.refuzz_test import RefuzzTester
from src.verification.verification_gate import VerificationGate
from src.verification.verification_report import VerificationReport


TARGET = "workspace/patched/vulnerable_c2.py"
REPORT_PATH = "artifacts/verification_report.json"


def run_verification():
    security_result = SecurityTester().test_command_injection(
        TARGET
    )

    regression_result = RegressionTester().test_diagnostic_functionality(
        TARGET
    )

    refuzz_result = RefuzzTester().test(
        TARGET
    )

    results = {
        "security_test": security_result,
        "regression_test": regression_result,
        "refuzz": refuzz_result,
    }

    gate = VerificationGate()
    gate_result = gate.evaluate(results)

    report_builder = VerificationReport()

    report = report_builder.build_report(
        TARGET,
        results,
        gate_result
    )

    report_builder.save(
        report,
        REPORT_PATH
    )

    return report


if __name__ == "__main__":
    final_report = run_verification()

    print(
        json.dumps(
            final_report,
            indent=4
        )
    )

    print(
        f"\nVerification report saved to: {REPORT_PATH}"
    )