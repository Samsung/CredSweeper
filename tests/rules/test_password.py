from typing import List

import pytest

from .common import BaseTestCommentRule, BaseTestNoQuotesRule, BaseTestRule


class TestPassword(BaseTestRule):
    @pytest.fixture(params=[["password = \"cackle!\""], ["gi_reo_gi_passwd = \"cackle!\""], ["pwd = \"cackle!\""],
                            ["data[\"pwd\"] = \"cackle!\""]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Password"


class TestPasswordNoQuotes(BaseTestNoQuotesRule):
    @pytest.fixture(params=[["password = cackle!"], ["gi_reo_gi_passwd = cackle!"], ["pwd = cackle!"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Password"


class TestPasswordComment(BaseTestCommentRule):
    @pytest.fixture(params=[["# password = cackle!"], ["# gi_reo_gi_passwd = cackle!"], ["# pwd = cackle!"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Password"
