from typing import List

import pytest

from .common import BaseTestRule


class TestGithubKey(BaseTestRule):

    @pytest.fixture(params=[["git_token = \"gireogicracklecrackle1231567190113416781\""]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Github Old Token"
