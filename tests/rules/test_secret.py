from typing import List

import pytest

from .common import BaseTestCommentRule, BaseTestNoQuotesRule, BaseTestRule


class TestSecret(BaseTestRule):

    @pytest.fixture(params=[["secret = \"cackle!\""]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Secret"


class TestSecretNoQuotes(BaseTestNoQuotesRule):

    @pytest.fixture(params=[["secret = cackle!"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Secret"


class TestSecretComment(BaseTestCommentRule):

    @pytest.fixture(params=[["# secret = cackle!"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Secret"
