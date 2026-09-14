import json

from src.analysis.engine import AnalysisEngine
from src.analysis.reasoning_adapter import (
    convert_analysis_to_evidence,
)


def main():
    engine = AnalysisEngine()

    analysis_result = engine.analyze(
        "examples/vulnerable_c2.py"
    )

    evidence = convert_analysis_to_evidence(
        analysis_result
    )

    print(
        json.dumps(
            evidence,
            indent=2
        )
    )


if __name__ == "__main__":
    main()