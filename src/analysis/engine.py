from .static_analyzer import analyze_file
from .dynamic_analyzer import DynamicAnalyzer
from .fuzzer import SecurityFuzzer


class AnalysisEngine:

    def analyze(self, file_path: str) -> dict:
        # 1. Run static analysis
        static_findings = analyze_file(file_path)

        # 2. Generate controlled fuzzing inputs
        fuzzer = SecurityFuzzer()
        fuzz_cases = fuzzer.generate_cases()

        # 3. Execute controlled inputs against the target
        dynamic_analyzer = DynamicAnalyzer()

        dynamic_observations = []

        for case in fuzz_cases:
            observation = dynamic_analyzer.analyze_observation(
                target_path=file_path,
                input_value=case.input_value,
            )

            dynamic_observations.append(
                observation.to_dict()
            )

        # 4. Return one combined analysis result
        return {
            "target": file_path,

            "static_findings": [
                finding.to_dict()
                for finding in static_findings
            ],

            "fuzz_cases": [
                {
                    "input": case.input_value,
                    "category": case.category,
                }
                for case in fuzz_cases
            ],

            "dynamic_observations": dynamic_observations,
        }