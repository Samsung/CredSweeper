from typing import List

import pytest

from .common import BaseTestRule


class TestPicaticKey(BaseTestRule):
    @pytest.fixture(params=[["sk_live_gireogicracklegireogicrackle1231"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Picatic API Key"
