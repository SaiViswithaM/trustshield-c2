from collections import defaultdict


class EvidenceFusion:

    def normalize(self, evidence):
        """
        Convert findings from different security-analysis
        engines into one common format.
        """

        normalized = []

        for finding in evidence.get("findings", []):

            normalized.append({
                "source": finding.get("source", "unknown"),
                "type": finding.get("type", "unknown"),
                "severity": finding.get("severity", "UNKNOWN"),
                "confidence": finding.get("confidence", 0.0),
                "location": finding.get("location", "unknown"),
                "evidence": finding.get("evidence", ""),
            })

        return normalized

    def group_by_type(self, findings):
        """
        Group findings that may represent the same
        vulnerability type.
        """

        groups = defaultdict(list)

        for finding in findings:
            groups[finding["type"]].append(finding)

        return dict(groups)

    def fuse(self, evidence):
        """
        Combine and correlate security findings.
        """

        normalized = self.normalize(evidence)

        groups = self.group_by_type(normalized)

        candidates = []

        for vulnerability_type, findings in groups.items():

            sources = sorted(
                set(
                    finding["source"]
                    for finding in findings
                )
            )

            candidates.append({
                "candidate": vulnerability_type,
                "sources": sources,
                "evidence_count": len(findings),
                "findings": findings,
                "corroborated": len(sources) >= 2
            })

        return {
            "target": evidence.get("target"),
            "candidates": candidates
        }


if __name__ == "__main__":

    sample_evidence = {
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

    fusion = EvidenceFusion()

    result = fusion.fuse(sample_evidence)

    import json

    print(json.dumps(result, indent=4))