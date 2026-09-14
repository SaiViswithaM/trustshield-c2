import subprocess


def diagnostic(user_input: str):
    command = f"ping {user_input}"
    return subprocess.run(command, shell=True)


if __name__ == "__main__":
    diagnostic("127.0.0.1")