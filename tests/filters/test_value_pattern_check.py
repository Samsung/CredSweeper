import unittest
from unittest.mock import MagicMock

import pytest

from credsweeper.config import Config
from credsweeper.filters import ValuePatternCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValuePatternCheck(unittest.TestCase):

    def setUp(self) -> None:
        self.config = MagicMock(spec=Config)
        self.config.pattern_len = 4
        self.config.pem_pattern_len = 5

    def test_equal_pattern_check_n(self) -> None:
        self.assertFalse(ValuePatternCheck(self.config).equal_pattern_check("Crackle123"))
        self.assertFalse(ValuePatternCheck(self.config).equal_pattern_check("IEEE32441"))
        self.assertFalse(ValuePatternCheck(self.config).equal_pattern_check("Pass..."))

    def test_equal_pattern_check_p(self) -> None:
        self.assertTrue(ValuePatternCheck(self.config).equal_pattern_check("AAAABCD"))
        self.assertTrue(ValuePatternCheck(self.config).equal_pattern_check("-------BEGIN"))
        self.config.pattern_len = 8
        self.assertFalse(ValuePatternCheck(self.config).equal_pattern_check("-------BEGIN"))

    def test_ascending_pattern_check_n(self) -> None:
        self.assertFalse(ValuePatternCheck(self.config).ascending_pattern_check("Crackle123"))
        self.assertFalse(ValuePatternCheck(self.config).ascending_pattern_check("Crackle987654321"))

    def test_ascending_pattern_check_p(self) -> None:
        self.assertTrue(ValuePatternCheck(self.config).ascending_pattern_check("Crackle1234"))
        self.assertTrue(ValuePatternCheck(self.config).ascending_pattern_check("Cracklefgh"))

    def test_descending_pattern_check_n(self) -> None:
        self.assertFalse(ValuePatternCheck(self.config).descending_pattern_check("Crackle321"))
        self.assertFalse(ValuePatternCheck(self.config).descending_pattern_check("Crackle123456789"))

    def test_descending_pattern_check_p(self) -> None:
        self.assertTrue(ValuePatternCheck(self.config).descending_pattern_check("Crackle4321"))
        self.assertTrue(ValuePatternCheck(self.config).descending_pattern_check("Crackledcba"))


class TestValuePatternCheckFixture:

    def test_value_similarity_check_p(self, file_path: pytest.fixture, config: Config,
                                      success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line, pattern=LINE_VALUE_PATTERN)
        assert ValuePatternCheck(config).run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["Crackle4444", "Crackle1234", "Crackle4321"])
    def test_value_similarity_check_n(self, file_path: pytest.fixture, config: Config, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValuePatternCheck(config).run(line_data, DUMMY_ANALYSIS_TARGET) is True

    def test_value_similarity_check_none_value_n(self, file_path: pytest.fixture, config: Config,
                                                 success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line)
        assert ValuePatternCheck(config).run(line_data, DUMMY_ANALYSIS_TARGET) is True
