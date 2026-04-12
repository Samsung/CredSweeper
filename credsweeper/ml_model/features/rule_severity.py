from credsweeper.common.constants import Severity
from credsweeper.credentials.candidate import Candidate
from credsweeper.ml_model.features.feature import Feature


class RuleSeverity(Feature):
    """Categorical feature that corresponds to rule name."""

    def extract(self, candidate: Candidate) -> float:
        match candidate.severity:
            case Severity.CRITICAL:
                return 1.0
            case Severity.HIGH:
                return 0.75
            case Severity.MEDIUM:
                return 0.5
            case Severity.LOW:
                return 0.25
            case Severity.INFO:
                return 0.0
            case _:
                raise ValueError(f"Unknown type of severity: {candidate.severity}")
