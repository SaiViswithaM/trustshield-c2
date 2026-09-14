import json

from src.analysis.engine import AnalysisEngine
from src.analysis.reasoning_adapter import (
    convert_analysis_to_evidence,
)
from src.reasoning.evidence_fusion import EvidenceFusion


def main():
    # Member 2: analyze the source code
    analysis_engine = AnalysisEngine()

    analysis_result = analysis_engine.analyze(
        "examples/vulnerable_c2.py"
    )

    # Member 2 → Member 1 adapter
    evidence = convert_analysis_to_evidence(
        analysis_result
    )

    # Member 1: fuse the evidence
    fusion_engine = EvidenceFusion()

    fused_result = fusion_engine.fuse(
        evidence
    )

    print("=== MEMBER 2 EVIDENCE ===")
    print(
        json.dumps(
            evidence,
            indent=2
        )
    )

    print("\n=== MEMBER 1 EVIDENCE FUSION ===")
    print(
        json.dumps(
            fused_result,
            indent=2
        )
    )


if __name__ == "__main__":
    main()