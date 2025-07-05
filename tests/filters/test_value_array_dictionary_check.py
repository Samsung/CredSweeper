import pytest

from credsweeper.filters import ValueArrayDictionaryCheck
from credsweeper.rules.rule import Rule
from tests.filters.conftest import DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueArrayDictionaryCheck:

    @pytest.fixture
    def token_rule(self, config) -> Rule:
        token_rule_without_filters = {
            "name": "Password",
            "severity": "medium",
            "confidence": "moderate",
            "type": "keyword",
            "values": ["pass"],
            "filter_type": [ValueArrayDictionaryCheck.__name__],
            "use_ml": True,
            "min_line_len": 0,
            "target": ["code", "doc"],
        }
        rule = Rule(config, token_rule_without_filters)
        return rule

    def test_value_array_dictionary_p(self, token_rule: Rule, file_path: pytest.fixture,
                                      success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line, pattern=token_rule.patterns[0])
        assert ValueArrayDictionaryCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", [
        "passwd = values[k+1:j]",
        "passwd = values[i]",
        "passwd = values[145]",
        "passwd = values[token_id]",
    ])
    def test_value_array_dictionary_n(self, token_rule: Rule, file_path: pytest.fixture, line: str) -> None:
        """Evaluate that filter do remove calls to arrays and arrays declarations"""
        line_data = get_line_data(file_path, line=line, pattern=token_rule.patterns[0])
        assert ValueArrayDictionaryCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True

    @pytest.mark.parametrize("line", [
        '{"password":[{"id":"09b51f37-8583-17ae-2a50-246c1b63150e","use":"alg","k":"XcFt0hJ4kA-1D9L37ZGu2_P"},{"kty"',
        "password = passwords['user1']",
        "password = passwords('user1')",
        "passwd[i] = 'root'",
        "users[i] = {passwd: 'root'}",
        "user = {passwd: 'root'}",
        "passwd = {'root'}",
        "user = get_user_data(passwd='root', user=users[i])",
        "user = get_user_data(user=users[i], passwd='root')",
    ])
    def test_array_assignment_n(self, token_rule: Rule, file_path: pytest.fixture, line: str) -> None:
        """Evaluate that filter do not remove assignments to array or dictionary declaration"""
        line_data = get_line_data(file_path, line=line, pattern=token_rule.patterns[0])
        assert ValueArrayDictionaryCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False
