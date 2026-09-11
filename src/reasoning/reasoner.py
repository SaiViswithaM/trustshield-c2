import json
import os

from dotenv import load_dotenv
from openai import OpenAI

from src.reasoning.evidence_fusion import EvidenceFusion
from src.reasoning.prompts import (
    SYSTEM_PROMPT,
    build_user_prompt
)

load_dotenv()


class OpenRouterCyberReasoner:

    def __init__(self):
        api_key = os.getenv("OPENROUTER_API_KEY")

        if not api_key:
            raise RuntimeError(
                "OPENROUTER_API_KEY is not set. "
                "Check your .env file."
            )

        self.client = OpenAI(
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1"
        )

        self.evidence_fusion = EvidenceFusion()

    def analyse(self, evidence):

        fused_evidence = self.evidence_fusion.fuse(evidence)

        prompt = build_user_prompt(fused_evidence)

        response = self.client.chat.completions.create(
            model="openrouter/free",
            messages=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.1
        )

        output = response.choices[0].message.content

        return json.loads(output)


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

    reasoner = OpenRouterCyberReasoner()

    result = reasoner.analyse(evidence)

    print(json.dumps(result, indent=4))