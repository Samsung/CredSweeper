import pytest

from credsweeper.filters import ValueSimilarityCheck
from credsweeper.rules.rule import Rule
from tests.filters.conftest import DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueSimilarityCheck:

    @pytest.fixture
    def password_rule(self, config) -> Rule:
        pass_rule_without_filters = {
            "name": "Password",
            "severity": "medium",
            "confidence": "moderate",
            "type": "keyword",
            "values": ["password|passwd|pwd"],
            "use_ml": True,
            "min_line_len": 0,
            "target": ["code", "doc"],
        }
        rule = Rule(config, pass_rule_without_filters)
        return rule

    def test_value_similarity_check_p(self, password_rule: Rule, file_path: str, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path=file_path, line=success_line, pattern=password_rule.patterns[0])
        assert ValueSimilarityCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize(
        "line",
        ["password = 'password1'", "password = 'password123'", "pwd=$PWD", '"password": "password=`$vc1rQ5eBW*S`"'])
    def test_value_similarity_check_n(self, password_rule: Rule, file_path: str, line: str) -> None:
        line_data = get_line_data(file_path=file_path, line=line, pattern=password_rule.patterns[0])
        assert ValueSimilarityCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
