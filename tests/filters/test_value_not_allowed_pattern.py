import pytest

from credsweeper.filters import ValueNotAllowedPatternCheck
from credsweeper.rules import Rule
from tests.filters.conftest import DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueLastWordCheck:

    @pytest.fixture
    def token_rule(self, config) -> Rule:
        token_rule_without_filters = {
            "name": "pass",
            "severity": "medium",
            "confidence": "moderate",
            "type": "keyword",
            "values": ["pass"],
            "filter_type": [ValueNotAllowedPatternCheck.__name__],
            "use_ml": True,
            "min_line_len": 0,
            "validations": [],
            "target": ["code", "doc"],
        }
        rule = Rule(config, token_rule_without_filters)
        return rule

    def test_value_last_word_check_p(self, token_rule: Rule, file_path: pytest.fixture,
                                     success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line, pattern=token_rule.patterns[0])
        assert ValueNotAllowedPatternCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["passwords: [{", "passwords = List<secret>", "passwords = \\n"])
    def test_value_last_word_check_n(self, token_rule: Rule, file_path: pytest.fixture, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=token_rule.patterns[0])
        assert ValueNotAllowedPatternCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True

    def test_value_last_word_check_none_value_n(self, file_path: pytest.fixture, success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line)
        assert ValueNotAllowedPatternCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
