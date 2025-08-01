from typing import List

import pytest

from credsweeper.file_handler.string_content_provider import StringContentProvider
from .common import BaseTestCommentRule, BaseTestNoQuotesRule, BaseTestRule


class TestToken(BaseTestRule):

    @pytest.fixture(params=[["gi_reo_gi_token = \"@@cacklecackle_gi_reo_gi@@\""]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Token"


class TestTokenNoQuotes(BaseTestNoQuotesRule):

    @pytest.fixture(params=[["gi_reo_gi_token = @@cacklecackle_gi_reo_gi@@"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Token"


class TestTokenComment(BaseTestCommentRule):

    @pytest.fixture(params=[["# gi_reo_gi_token = @@cacklecackle_gi_reo_gi@@"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Token"


class TestTokenWhitespaceBeforeQuote:

    @pytest.fixture
    def lines(self) -> List[str]:
        lines = "    \"gi_reo_gi_token\": \"@@cacklecackle_gi_reo_gi@@\"".splitlines()
        return lines

    @pytest.fixture
    def rule_name(self) -> str:
        return "Token"

    def test_scan_whitespace_before_quote_p(self, file_path: pytest.fixture, lines: pytest.fixture,
                                            scanner: pytest.fixture) -> None:
        provider = StringContentProvider(lines)
        assert len(scanner.scan(provider)) == 1
