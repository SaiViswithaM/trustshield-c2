import subprocess


def diagnostic(command):
    """
    Simulated C2 diagnostic function.

    INTENTIONALLY VULNERABLE:
    User-controlled input is passed to a shell.
    This file exists only for local security testing.
    """

    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True
    )

    return result.stdout


def main():
    print("TRUSTSHIELD-C2 simulated diagnostic service")

    command = input("Enter diagnostic command: ")

    try:
        output = diagnostic(command)
        print("Diagnostic output:")
        print(output)
    except Exception as exc:
        print(f"Diagnostic error: {exc}")


if __name__ == "__main__":
    main()