import pytest
from typing import List

class BaseTestRule:
    def test_scan_p(self, file_path: pytest.fixture, lines: pytest.fixture, scanner: pytest.fixture) -> None:
        assert len(scanner.scan(file_path, lines)) == 1

    @pytest.mark.parametrize("lines", [[""], ["String secret = new String()"], ["SZa6TWGF2XuWdl7c2s2xB1iSlnZJLbvH"]])
    def test_scan_n(self, file_path: pytest.fixture, lines: List[str], scanner: pytest.fixture) -> None:
        assert len(scanner.scan(file_path, lines)) == 0


class BaseTestNoQuotesRule:
    """
    If secret declared in a code file (".cpp", ".py", etc) in should be escaped with quotes. Otherwise it cannot be a
     string secret, as no string literal declared.
    Exceptions: comments. In comment secret can be unquoted

    This test checks if unquoted password is not comment and declared in code file.
    """
    def test_scan_quote_p(self, file_path: pytest.fixture, lines: pytest.fixture, scanner: pytest.fixture) -> None:
        assert len(scanner.scan(file_path, lines)) == 1

    def test_scan_quote_n(self, python_file_path: pytest.fixture, lines: pytest.fixture,
                          scanner: pytest.fixture) -> None:
        assert len(scanner.scan(python_file_path, lines)) == 0


class BaseTestCommentRule:
    """
    If secret declared in a code file (".cpp", ".py", etc) in should be escaped with quotes. Otherwise it cannot be a
     string secret, as no string literal declared.
    Exceptions: comments. In comment secret can be unquoted

    This test checks if unquoted password is comment in code file
    """
    def test_scan_comment_p(self, python_file_path: pytest.fixture, lines: pytest.fixture,
                            scanner: pytest.fixture) -> None:
        assert len(scanner.scan(python_file_path, lines)) == 1

    def test_scan_comment_n(self, python_file_path: pytest.fixture, lines: pytest.fixture,
                            scanner: pytest.fixture) -> None:
        lines = [f"\\{line}" for line in lines]
        assert len(scanner.scan(python_file_path, lines)) == 0


class BaseTestMultiRule:
    def test_scan_line_data_p(self, file_path: pytest.fixture, lines: pytest.fixture, scanner: pytest.fixture) -> None:

        assert len(scanner.scan(file_path, lines)[0].line_data_list) == 2

    def test_scan_line_data_n(self, file_path: pytest.fixture, scanner: pytest.fixture) -> None:
        assert len(scanner.scan(file_path, [""])) == 0
