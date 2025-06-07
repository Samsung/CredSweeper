from typing import List

import pytest

from credsweeper.file_handler.string_content_provider import StringContentProvider


class BaseTestRule:

    def test_scan_p(self, file_path: pytest.fixture, lines: pytest.fixture,
                    scanner_without_filters: pytest.fixture) -> None:
        provider = StringContentProvider(lines, file_path=file_path)
        scan_result = scanner_without_filters.scan(provider)
        assert len(scan_result) == 1, (lines, scan_result)

    @pytest.mark.parametrize("lines",
                             [[""], ["String secret = new String('p****');"], ["SZa6TWGF2XuWdl7c2s2xB1iSlnZJLbvH"]])
    def test_scan_n(self, file_path: pytest.fixture, lines: List[str], scanner: pytest.fixture) -> None:
        provider = StringContentProvider(lines, file_path=file_path)
        scan_result = scanner.scan(provider)
        assert len(scan_result) == 0, scan_result[0]


class BaseTestNoQuotesRule:
    """
    If secret declared in a code file (".cpp", ".py", etc) in should be escaped with quotes. Otherwise it cannot be a
     string secret, as no string literal declared.
    Exceptions: comments. In comment secret can be unquoted

    This test checks if unquoted password is not comment and declared in code file.
    """

    def test_scan_quote_p(self, file_path: pytest.fixture, lines: pytest.fixture, scanner: pytest.fixture) -> None:
        provider = StringContentProvider(lines, file_path=file_path)
        scan_result = scanner.scan(provider)
        assert len(scan_result) == 1, (lines, scan_result)

    def test_scan_quote_n(self, python_file_path: pytest.fixture, lines: pytest.fixture,
                          scanner: pytest.fixture) -> None:
        provider = StringContentProvider(lines, file_path=python_file_path)
        scan_result = scanner.scan(provider)
        assert len(scan_result) == 0, scan_result


class BaseTestCommentRule:
    """
    If secret declared in a code file (".cpp", ".py", etc) in should be escaped with quotes. Otherwise it cannot be a
     string secret, as no string literal declared.
    Exceptions: comments. In comment secret can be unquoted

    This test checks if unquoted password is comment in code file
    """

    def test_scan_comment_p(self, python_file_path: pytest.fixture, lines: pytest.fixture,
                            scanner: pytest.fixture) -> None:
        provider = StringContentProvider(lines, file_path=python_file_path)
        scan_result = scanner.scan(provider)
        assert len(scan_result) == 1, (lines, scan_result)

    def test_scan_comment_n(self, python_file_path: pytest.fixture, lines: pytest.fixture,
                            scanner: pytest.fixture) -> None:
        lines = [line[1:] for line in lines]
        provider = StringContentProvider(lines, file_path=python_file_path)
        scan_result = scanner.scan(provider)
        assert len(scan_result) == 0, scan_result


class BaseTestMultiRule:

    def test_scan_line_data_p(self, file_path: pytest.fixture, lines: pytest.fixture, scanner: pytest.fixture) -> None:
        provider = StringContentProvider(lines)
        scan_result = scanner.scan(provider)
        assert len(scan_result) != 0
        assert len(scan_result[0].line_data_list) == 2

    def test_scan_line_data_n(self, file_path: pytest.fixture, scanner: pytest.fixture) -> None:
        lines = [""]
        provider = StringContentProvider(lines)
        scan_result = scanner.scan(provider)
        assert len(scan_result) == 0
