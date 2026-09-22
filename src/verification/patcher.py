from pathlib import Path
import shutil


class PatchApplier:
    """
    Creates an isolated patched copy of the target software.

    The original target is never modified directly.
    """

    def create_workspace(self, target_path, workspace_path):
        target = Path(target_path)
        workspace = Path(workspace_path)

        if not target.exists():
            raise FileNotFoundError(
                f"Target file not found: {target}"
            )

        original_dir = workspace / "original"
        patched_dir = workspace / "patched"

        original_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        patched_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        original_target = original_dir / target.name
        patched_target = patched_dir / target.name

        shutil.copy2(target, original_target)
        shutil.copy2(target, patched_target)

        return {
            "original": str(original_target),
            "patched": str(patched_target),
            "workspace": str(workspace),
        }

    def prepare_patch(
        self,
        remediation: dict,
        target_path: str,
        workspace_path: str = "workspace",
    ):
        """
        Validate remediation information and prepare
        an isolated patch workspace.
        """

        if not remediation:
            raise ValueError(
                "Remediation input is empty."
            )

        required_fields = [
            "vulnerability",
            "root_cause",
            "affected_location",
            "recommended_remediation",
            "verification_requirements",
        ]

        missing_fields = [
            field
            for field in required_fields
            if field not in remediation
        ]

        if missing_fields:
            raise ValueError(
                f"Missing remediation fields: {missing_fields}"
            )

        workspace_result = self.create_workspace(
            target_path,
            workspace_path
        )

        return {
            **workspace_result,
            "vulnerability": remediation[
                "vulnerability"
            ],
            "root_cause": remediation[
                "root_cause"
            ],
            "affected_location": remediation[
                "affected_location"
            ],
            "recommended_remediation": remediation[
                "recommended_remediation"
            ],
            "verification_requirements": remediation[
                "verification_requirements"
            ],
            "patch_status": "READY_FOR_PATCH",
        }

    def apply_command_injection_patch(
        self,
        patched_path: str,
    ):
        """
        Apply the known command-injection remediation
        to the isolated patched copy.

        This prototype intentionally performs a narrow,
        deterministic transformation rather than executing
        arbitrary LLM-generated code.
        """

        patched_file = Path(patched_path)

        if not patched_file.exists():
            raise FileNotFoundError(
                f"Patched file not found: {patched_file}"
            )

        source = patched_file.read_text(
            encoding="utf-8"
        )

        vulnerable_pattern = """result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True
    )"""

        safe_pattern = """result = subprocess.run(
        command.split(),
        shell=False,
        capture_output=True,
        text=True
    )"""

        if vulnerable_pattern not in source:
            raise ValueError(
                "Expected vulnerable subprocess pattern "
                "was not found. Patch was not applied."
            )

        patched_source = source.replace(
            vulnerable_pattern,
            safe_pattern,
            1
        )

        patched_file.write_text(
            patched_source,
            encoding="utf-8"
        )

        return {
            "patched_file": str(patched_file),
            "patch_status": "PATCH_APPLIED",
            "change": (
                "Replaced shell=True with shell=False "
                "and passed command arguments as a list."
            ),
        }


if __name__ == "__main__":

    patcher = PatchApplier()

    remediation = {
        "vulnerability": "command_injection",
        "root_cause": (
            "subprocess.run uses shell=True "
            "with user-controlled input."
        ),
        "affected_location": (
            "examples/vulnerable_c2.py:13"
        ),
        "recommended_remediation": (
            "Remove shell=True and pass "
            "arguments as a list."
        ),
        "verification_requirements": [
            "Confirm shell=True is removed.",
            "Run controlled injection tests.",
            "Run regression tests.",
        ],
    }

    prepared = patcher.prepare_patch(
        remediation=remediation,
        target_path="examples/vulnerable_c2.py",
        workspace_path="workspace",
    )

    print("Patch preparation complete:")
    print(f"Original: {prepared['original']}")
    print(f"Patched:  {prepared['patched']}")
    print(f"Status:   {prepared['patch_status']}")

    patch_result = patcher.apply_command_injection_patch(
        prepared["patched"]
    )

    print("\nPatch application complete:")
    print(f"File:   {patch_result['patched_file']}")
    print(f"Status: {patch_result['patch_status']}")
    print(f"Change: {patch_result['change']}")