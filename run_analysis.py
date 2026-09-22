import json

from src.analysis.engine import AnalysisEngine


def main():
    engine = AnalysisEngine()

    result = engine.analyze(
        "examples/vulnerable_c2.py"
    )

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()