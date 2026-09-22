class VerificationGate:
    """
    Deterministic gate for deciding whether a remediation
    has been independently verified.
    """

    REQUIRED_CHECKS = [
        "security_test",
        "regression_test",
        "refuzz",
    ]

    def evaluate(self, results):
        """
        Evaluate verification results.

        Every required check must explicitly return PASS.
        Anything else results in NOT_VERIFIED.
        """

        statuses = {
            check: results.get(check, {}).get("status")
            for check in self.REQUIRED_CHECKS
        }

        failed_checks = [
            check
            for check, status in statuses.items()
            if status != "PASS"
        ]

        if failed_checks:
            return {
                "status": "NOT_VERIFIED",
                "verified": False,
                "failed_checks": failed_checks,
                "checks": statuses,
            }

        return {
            "status": "VERIFIED",
            "verified": True,
            "failed_checks": [],
            "checks": statuses,
        }


if __name__ == "__main__":
    gate = VerificationGate()

    verification_results = {
        "security_test": {
            "status": "PASS"
        },
        "regression_test": {
            "status": "PASS"
        },
        "refuzz": {
            "status": "PASS"
        },
    }

    result = gate.evaluate(verification_results)

    print(result)