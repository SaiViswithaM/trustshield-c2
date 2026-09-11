import json
import os

from dotenv import load_dotenv

load_dotenv()

from openai import OpenAI

from src.reasoning.evidence_fusion import EvidenceFusion
from src.reasoning.prompts import (
    SYSTEM_PROMPT,
    build_user_prompt
)


class OpenAICyberReasoner:
    def __init__(self):
        api_key = os.getenv("OPENAI_API_KEY")

        if not api_key:
            raise RuntimeError(
                "OPENAI_API_KEY is not set. "
                "Check your .env file."
            )

        self.client = OpenAI(api_key=api_key)
        self.evidence_fusion = EvidenceFusion()

    def analyse(self, evidence):
        fused_evidence = self.evidence_fusion.fuse(evidence)

        prompt = build_user_prompt(fused_evidence)

        response = self.client.responses.create(
            model="gpt-5.6",
            instructions=SYSTEM_PROMPT,
            input=prompt
        )

        return json.loads(response.output_text)


if __name__ == "__main__":

    evidence = {
        "target": "examples/vulnerable_c2.py",
        "findings": [
            {
                "source": "static_analysis",
                "type": "command_injection",
                "severity": "HIGH",
                "location": "diagnostic()",
                "evidence": "subprocess uses shell=True"
            },
            {
                "source": "fuzzing",
                "type": "command_injection",
                "severity": "HIGH",
                "location": "diagnostic()",
                "evidence": "unexpected behaviour observed"
            },
            {
                "source": "dynamic_analysis",
                "type": "command_injection",
                "severity": "HIGH",
                "location": "diagnostic()",
                "evidence": "user-controlled input reaches subprocess"
            }
        ]
    }

    reasoner = OpenAICyberReasoner()

    result = reasoner.analyse(evidence)

    print(json.dumps(result, indent=4))