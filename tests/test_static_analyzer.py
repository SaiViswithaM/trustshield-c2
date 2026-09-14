from src.analysis.static_analyzer import analyze_file


def test_command_injection_detection():
    findings = analyze_file("examples/vulnerable_c2.py")

    assert len(findings) >= 1

    finding = findings[0]

    assert finding.vulnerability == "command_injection"
    assert finding.severity == "HIGH"
    assert finding.rule == "PY001"