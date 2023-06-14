import pytest

from credsweeper.filters import ValueSimilarityCheck, VariableNotAllowedPatternCheck
from credsweeper.rules import Rule
from tests.filters.conftest import DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueSimilarityCheck:

    @pytest.fixture
    def password_rule(self, config) -> Rule:
        pass_rule_without_filters = {
            "name": "Password",
            "severity": "medium",
            "type": "keyword",
            "values": ["password|passwd|pwd"],
            "filter_type": [VariableNotAllowedPatternCheck.__name__],
            "use_ml": True,
            "usage_list": ["src", "doc"],
            "validations": []
        }
        rule = Rule(config, pass_rule_without_filters)
        return rule

    def test_value_similarity_check_p(self, password_rule: Rule, file_path: str, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path=file_path, line=success_line, pattern=password_rule.patterns[0])
        assert ValueSimilarityCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["password = 'password1'", "password = 'password123'"])
    def test_value_similarity_check_n(self, password_rule: Rule, file_path: str, line: str) -> None:
        line_data = get_line_data(file_path=file_path, line=line, pattern=password_rule.patterns[0])
        assert ValueSimilarityCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
