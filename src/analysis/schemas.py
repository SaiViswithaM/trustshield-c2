from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class SecurityFinding:
    source: str
    rule: str
    vulnerability: str
    severity: str
    confidence: float
    file: str
    line: int
    evidence: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)