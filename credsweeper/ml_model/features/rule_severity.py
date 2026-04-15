from credsweeper.common.constants import Severity
from credsweeper.credentials.candidate import Candidate
from credsweeper.ml_model.features.feature import Feature


class RuleSeverity(Feature):
    """Categorical feature that corresponds to rule name."""

    def extract(self, candidate: Candidate) -> float:
        if Severity.CRITICAL == candidate.severity:
            return 1.0
        if Severity.HIGH == candidate.severity:
            return 0.75
        if Severity.MEDIUM == candidate.severity:
            return 0.5
        if Severity.LOW == candidate.severity:
            return 0.25
        if Severity.INFO == candidate.severity:
            return 0.0
        raise ValueError(f"Unknown type of severity: {candidate.severity}")
