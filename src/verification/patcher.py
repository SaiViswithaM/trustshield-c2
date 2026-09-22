from pathlib import Path
import shutil


class PatchApplier:
    """
    Creates a separate patched copy of the target software.

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

        original_dir.mkdir(parents=True, exist_ok=True)
        patched_dir.mkdir(parents=True, exist_ok=True)

        original_target = original_dir / target.name
        patched_target = patched_dir / target.name

        shutil.copy2(target, original_target)
        shutil.copy2(target, patched_target)

        return {
            "original": str(original_target),
            "patched": str(patched_target),
            "workspace": str(workspace),
        }


if __name__ == "__main__":
    patcher = PatchApplier()

    result = patcher.create_workspace(
        "examples/vulnerable_c2.py",
        "workspace"
    )

    print("Patch workspace created:")
    print(f"Original: {result['original']}")
    print(f"Patched:  {result['patched']}")