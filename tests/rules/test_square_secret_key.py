from typing import List

import pytest

from .common import BaseTestRule


class TestSquareSecretKey(BaseTestRule):
    @pytest.fixture(params=[["sq0csp-GIREOGICRACKLEGIREOGICRACKLEGIREOGICRACKLE1"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Square OAuth Secret"
