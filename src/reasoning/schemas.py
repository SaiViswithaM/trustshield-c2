from dataclasses import dataclass, field
from typing import List


@dataclass
class VulnerabilityAssessment:
    vulnerability: str
    severity: str
    confidence: str
    root_cause: str
    affected_location: str
    remediation: str
    verification_requirements: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "vulnerability": self.vulnerability,
            "severity": self.severity,
            "confidence": self.confidence,
            "root_cause": self.root_cause,
            "affected_location": self.affected_location,
            "remediation": self.remediation,
            "verification_requirements": self.verification_requirements,
        }