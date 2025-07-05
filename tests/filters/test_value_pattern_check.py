import unittest
from unittest.mock import MagicMock

import pytest

from credsweeper.config.config import Config
from credsweeper.filters import ValuePatternCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValuePatternCheck(unittest.TestCase):

    def setUp(self) -> None:
        self.config = MagicMock(spec=Config)
        self.config.pattern_len = 4

    def test_duple_pattern_check_n(self) -> None:
        self.assertFalse(ValuePatternCheck(self.config).duple_pattern_check("20201030", 4))
        self.assertFalse(ValuePatternCheck(self.config).duple_pattern_check("01000101", 4))
        self.assertFalse(ValuePatternCheck(self.config).duple_pattern_check("10305070", 4))
        self.assertFalse(ValuePatternCheck(self.config).duple_pattern_check("11224433", 4))
        self.assertFalse(ValuePatternCheck(self.config).duple_pattern_check("11000000", 4))

    def test_duple_pattern_check_p(self) -> None:
        self.assertTrue(ValuePatternCheck(self.config).duple_pattern_check("11223344", 4))
        self.assertTrue(ValuePatternCheck(self.config).duple_pattern_check("010101010", 4))
        self.assertTrue(ValuePatternCheck(self.config).duple_pattern_check("40302010", 4))

    def test_equal_pattern_check_n(self) -> None:
        self.assertFalse(ValuePatternCheck(self.config).equal_pattern_check("Crackle123", 4))
        self.assertFalse(ValuePatternCheck(self.config).equal_pattern_check("IEEE32441", 4))
        self.assertFalse(ValuePatternCheck(self.config).equal_pattern_check("Pass...", 4))
        self.assertFalse(ValuePatternCheck(pattern_len=4).equal_pattern_check("Pass:\\n        Crackle123", 5))

    def test_equal_pattern_check_p(self) -> None:
        self.assertTrue(ValuePatternCheck(self.config).equal_pattern_check("AAAABCD", 4))
        self.assertTrue(ValuePatternCheck(pattern_len=4).equal_pattern_check("-------BEGIN", 4))
        self.assertFalse(ValuePatternCheck(pattern_len=8).equal_pattern_check("-------BEGIN", 4))

    def test_ascending_pattern_check_n(self) -> None:
        self.assertFalse(ValuePatternCheck(self.config).ascending_pattern_check("Crackle123", 4))
        self.assertFalse(ValuePatternCheck(pattern_len=4).ascending_pattern_check("Crackle987654321", 4))

    def test_ascending_pattern_check_p(self) -> None:
        self.assertTrue(ValuePatternCheck(self.config).ascending_pattern_check("Crackle1234", 4))
        self.assertTrue(ValuePatternCheck(pattern_len=4).ascending_pattern_check("Cracklefgh", 4))

    def test_descending_pattern_check_n(self) -> None:
        self.assertFalse(ValuePatternCheck(self.config).descending_pattern_check("Crackle321", 4))
        self.assertFalse(ValuePatternCheck(pattern_len=4).descending_pattern_check("Crackle123456789", 5))

    def test_descending_pattern_check_p(self) -> None:
        self.assertTrue(ValuePatternCheck(self.config).descending_pattern_check("Crackle4321", 4))
        self.assertTrue(ValuePatternCheck(pattern_len=4).descending_pattern_check("Crackledcba", 4))


class TestValuePatternCheckFixture:

    def test_value_similarity_check_p(self, file_path: pytest.fixture, config: Config,
                                      success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line, pattern=LINE_VALUE_PATTERN)
        assert ValuePatternCheck(config).run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", [
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526", "Crackle4444", "Crackle1234",
        "Crackle4321", "@$%", "a5", "_"
    ])
    def test_value_similarity_check_n(self, file_path: pytest.fixture, config: Config, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValuePatternCheck(config).run(line_data, DUMMY_ANALYSIS_TARGET) is True
