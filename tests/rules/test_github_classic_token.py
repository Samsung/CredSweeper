from typing import List

import pytest

from .common import BaseTestRule


class TestClassicToken(BaseTestRule):

    @pytest.fixture(params=[  #
        ["ghu_00000000000000000000000000000004WZ4EQ"]  #
    ])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Github Classic Token"
