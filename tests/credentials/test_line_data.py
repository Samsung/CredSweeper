import re
import unittest

import pytest

from credsweeper.common.constants import MAX_LINE_LENGTH, StartEnd
from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.utils import Util
from tests import AZ_STRING


class TestLineData:

    @pytest.mark.parametrize("line", [
        '"url" : "https://my.site?a=b&{}=ngh679x&c=d"',
        '"url" : "https://my.site?{}=ngh679x&c=d"',
        '"url" : "https://my.site?a=b&{}=ngh679x"',
    ])
    @pytest.mark.parametrize("var_name, rule_name", [("mysecret", "Secret"), ("password", "Password"),
                                                     ("aws_token", "Token")])
    def test_url_params_p(self, file_path: pytest.fixture, rule: pytest.fixture, line: str, var_name: str,
                          rule_name: str, config: Config) -> None:
        """
        Test that URL args are parsed correctly with regard to ? and & characters.
        Rerun few times with different variable names to assure that different rules behave in a same way
        """
        formatted_line = line.format(var_name)
        line_data = LineData(config, formatted_line, 0, 1, file_path, Util.get_extension(file_path), "test_info",
                             rule.patterns[0])
        assert line_data.value == "ngh679x"
        assert line_data.variable == var_name

    @pytest.mark.parametrize("line", ['{} = "ngh679x"'])
    @pytest.mark.parametrize("var_name, rule_name", [("mysecret", "Secret"), ("password", "Password"),
                                                     ("aws_token", "Token")])
    def test_simple_case_p(self, file_path: pytest.fixture, rule: pytest.fixture, line: str, var_name: str,
                           rule_name: str, config: Config) -> None:
        """Check that most simple case for credentials is parsed correctly"""
        formatted_line = line.format(var_name)
        line_data = LineData(config, formatted_line, 0, 1, file_path, Util.get_extension(file_path), "test_info",
                             rule.patterns[0])
        assert line_data.value == "ngh679x"
        assert line_data.variable == var_name

    @pytest.mark.parametrize("line, varname, rule_name",
                             [('"my password": "ngh679x"', "my password", "Password"),
                              ('"my password in JSON": "ngh679x"', "my password in JSON", "Password")])
    def test_multiple_word_variable_name_p(self, file_path: pytest.fixture, rule: pytest.fixture, line: str,
                                           varname: str, rule_name: str, config: Config) -> None:
        """Check that if variable name contain spaces (like field in JSON) it would be parsed correctly"""
        line_data = LineData(config, line, 0, 1, file_path, Util.get_extension(file_path), "test_info",
                             rule.patterns[0])
        assert line_data.value == "ngh679x"
        assert line_data.variable == varname

    @pytest.mark.parametrize(
        "line", ['{} = my_func("ngh679x")', '{} = my_func(arg1="ngh679x")', '{} = my_func1(my_func2("ngh679x"))'])
    @pytest.mark.parametrize("var_name, rule_name", [("mysecret", "Secret"), ("password", "Password"),
                                                     ("aws_token", "Token")])
    def test_function_call_p(self, file_path: pytest.fixture, rule: pytest.fixture, line: str, var_name: str,
                             rule_name: str, config: Config) -> None:
        """Check that secrets in function arguments parsed in a correct way (without argument name)"""
        formatted_line = line.format(var_name)
        line_data = LineData(config, formatted_line, 0, 1, file_path, Util.get_extension(file_path), "test_info",
                             rule.patterns[0])
        assert line_data.value == "ngh679x"
        assert line_data.variable == var_name

    @pytest.mark.parametrize("line", [
        'something = my_func({}="ngh679x")',
        'something = my_func(a=b, {}="ngh679x")',
        'something = my_func(a=b, {}="ngh679x", c=d)',
    ])
    @pytest.mark.parametrize("var_name, rule_name", [("mysecret", "Secret"), ("password", "Password"),
                                                     ("aws_token", "Token")])
    def test_function_argument_p(self, file_path: pytest.fixture, rule: pytest.fixture, line: str, var_name: str,
                                 rule_name: str, config: Config) -> None:
        """Check that secrets in function arguments parsed in a correct way (with argument name)"""
        formatted_line = line.format(var_name)
        line_data = LineData(config, formatted_line, 0, 1, file_path, Util.get_extension(file_path), "test_info",
                             rule.patterns[0])
        assert line_data.value == "ngh679x"
        assert line_data.variable == var_name

    @pytest.mark.parametrize("line", [
        "./myprog --{}='ngh679x' --path=/home/me",
        "./myprog --{}=ngh679x --path=/home/me",
        "./myprog --{}=ngh679x -d library/mysql:5.7.13",
        "./myprog --{}=ngh679x >> logfile.log",
        "./myprog --{}=ngh679x | tee logfile.log",
        "./myprog --{}=ngh679x &> logfile.log",
        "./myprog --{}=ngh679x 2> logfile.log",
    ])
    @pytest.mark.parametrize("var_name, rule_name", [("mysecret", "Secret"), ("password", "Password"),
                                                     ("aws_token", "Token")])
    def test_cli_arguments_p(self, file_path: pytest.fixture, rule: pytest.fixture, line: str, var_name: str,
                             rule_name: str, config: Config) -> None:
        """Check credentials declared in CLI arguments"""
        formatted_line = line.format(var_name)
        line_data = LineData(config, formatted_line, 0, 1, file_path, Util.get_extension(file_path), "test_info",
                             rule.patterns[0])
        assert line_data.value == "ngh679x"
        assert line_data.variable == var_name

    @pytest.mark.parametrize("line", [
        "./myprog --{}=' --no-password ' --path=/home/me",
    ])
    @pytest.mark.parametrize("var_name, rule_name", [("password", "Password")])
    def test_cli_arguments_n(self, file_path: pytest.fixture, rule: pytest.fixture, line: str, var_name: str,
                             rule_name: str, config: Config) -> None:
        """Check clean_bash_parameters negative case """
        formatted_line = line.format(var_name)
        line_data = LineData(config, formatted_line, 0, 1, file_path, Util.get_extension(file_path), "test_info",
                             rule.patterns[0])
        assert line_data.variable == var_name


class TestLineDataStartEnd(unittest.TestCase):

    def test_start_end_p(self) -> None:
        """Check start-end of found credential"""

        line_data = LineData(None, "0123456789", 0, 1, "", "", "", re.compile(r"(?P<value>[3-7]+)"))
        self.assertEqual("34567", line_data.value)
        self.assertEqual(3, line_data.value_start)
        self.assertEqual(8, line_data.value_end)

    def test_search_start_end_p(self) -> None:
        """Check property search start-end"""
        line = "_" * MAX_LINE_LENGTH + "X" + "_" * MAX_LINE_LENGTH
        pattern = re.compile(r"(?P<value>X)")
        line_data = LineData(None, line, 0, 1, "", "", "", pattern, pattern.search(line))
        self.assertEqual("X", line_data.value)
        self.assertEqual(MAX_LINE_LENGTH, line_data.value_start)
        self.assertEqual(1 + MAX_LINE_LENGTH, line_data.value_end)

    def test_part_url_sanitize_p(self) -> None:
        line_data = LineData(None,
                             "39084?token=3487263-2384579834-234732875-345&key=DnBeiGdgy6253fytfdDHGg&hasToBeFound=2",
                             0, 1, "", "", "", re.compile(r"(?P<variable>token)(?P<separator>=)(?P<value>.+)"))
        self.assertEqual("token", line_data.variable)
        self.assertEqual("3487263-2384579834-234732875-345", line_data.value)

    def test_hash_text_n(self):
        self.assertEqual("", LineData.get_hash_or_subtext('', hashed=True))


    def test_hash_text_p(self):
        # $ echo -n "The quick brown fox jumps over the lazy dog" | sha256sum
        self.assertEqual("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
                         LineData.get_hash_or_subtext(AZ_STRING, hashed=True))

    def test_sub_text_n(self):
        subtext = LineData.get_hash_or_subtext(None, hashed=False, cut_pos=StartEnd(4, 9))
        self.assertIsNone(subtext)


    def test_sub_text_p(self):
        subtext = LineData.get_hash_or_subtext(AZ_STRING, hashed=False, cut_pos=StartEnd(4, 9))
        self.assertEqual("quick", subtext)
