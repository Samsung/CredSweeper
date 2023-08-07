import unittest
from unittest.mock import patch

from credsweeper.common.constants import Severity
from credsweeper.credentials import LineData, Candidate


class TestCandidate(unittest.TestCase):

    def test_candidate_category_p(self):
        with patch.object(LineData, LineData.initialize.__name__):
            candidate = Candidate(
                line_data_list=[],
                patterns=[],
                rule_name="rule_name",
                severity=Severity.INFO,
                config=None,
                category="TEST_CATEGORY")
            self.assertDictEqual(
                {
                    "api_validation": "NOT_AVAILABLE",
                    "category": "TEST_CATEGORY",
                    "line_data_list": [],
                    "ml_probability": None,
                    "ml_validation": "NOT_AVAILABLE",
                    "patterns": [],
                    "rule": "rule_name",
                    "severity": "info",
                    "use_ml": False}, candidate.to_json())

    def test_candidate_category_n(self):
        with patch.object(LineData, LineData.initialize.__name__):
            candidate = Candidate(
                line_data_list=[],
                patterns=[],
                rule_name="rule_name",
                severity=Severity.INFO,
                config=None)
            self.assertDictEqual(
                {
                    "api_validation": "NOT_AVAILABLE",
                    "category": "Other",
                    "line_data_list": [],
                    "ml_probability": None,
                    "ml_validation": "NOT_AVAILABLE",
                    "patterns": [],
                    "rule": "rule_name",
                    "severity": "info",
                    "use_ml": False}, candidate.to_json())
