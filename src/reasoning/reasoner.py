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

        # Step 1: Fuse evidence from independent analysis engines
        fused_evidence = self.evidence_fusion.fuse(evidence)

        # Step 2: Build the reasoning prompt
        prompt = build_user_prompt(fused_evidence)

        # Step 3: Ask the LLM to analyse the evidence
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
            temperature=0.1,
            response_format={
                "type": "json_object"
            }
        )

        # Step 4: Extract model output
        output = response.choices[0].message.content

        if not output:
            raise RuntimeError(
                "Cyber Reasoner returned an empty response."
            )

        output = output.strip()

        # Step 5: Handle accidental Markdown code fences
        if output.startswith("```"):
            output = (
                output
                .removeprefix("```json")
                .removeprefix("```")
                .strip()
            )

        if output.endswith("```"):
            output = output.removesuffix("```").strip()

        # Step 6: Parse structured JSON
        try:
            result = json.loads(output)

        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Cyber Reasoner returned invalid JSON. "
                f"Raw response: {output!r}"
            ) from exc

        # Step 7: Basic schema validation
        required_fields = [
            "vulnerability",
            "severity",
            "confidence",
            "root_cause",
            "affected_location",
            "remediation",
            "verification_requirements",
        ]

        missing_fields = [
            field
            for field in required_fields
            if field not in result
        ]

        if missing_fields:
            raise RuntimeError(
                "Cyber Reasoner returned incomplete JSON. "
                f"Missing fields: {missing_fields}"
            )

        # The verification requirements must be a list.
        if not isinstance(
            result["verification_requirements"],
            list
        ):
            raise RuntimeError(
                "Cyber Reasoner returned an invalid "
                "verification_requirements field."
            )

        return result


if __name__ == "__main__":

    # Example evidence for local testing.
    #
    # This represents the type of evidence that Member 2
    # sends to the Cyber Reasoner.
    evidence = {
        "target": "examples/vulnerable_c2.py",

        "findings": [

            {
                "source": "static_analysis",
                "type": "command_injection",
                "severity": "HIGH",
                "location": "examples/vulnerable_c2.py:13",
                "evidence": (
                    "subprocess.run uses shell=True"
                )
            },

            {
                "source": "fuzzing",
                "type": "command_injection",
                "severity": "HIGH",
                "location": "examples/vulnerable_c2.py:13",
                "evidence": (
                    "Controlled command-chaining payload "
                    "generated for runtime testing."
                )
            },

            {
                "source": "dynamic_analysis",
                "type": "command_injection",
                "severity": "HIGH",
                "location": "examples/vulnerable_c2.py:13",
                "evidence": (
                    "Controlled injection marker "
                    "INJECTION_MARKER was observed in "
                    "runtime output."
                )
            }
        ]
    }

    reasoner = OpenRouterCyberReasoner()

    result = reasoner.analyse(evidence)

    print(json.dumps(result, indent=4))