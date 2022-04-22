from typing import List

import pytest

from .common import BaseTestRule


class TestSquareClientID(BaseTestRule):

    @pytest.fixture(params=[["sq0atp-GIREOGICRACKLE12145178"], ["sq0idp-1230567912305-12305670"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Square Client ID"
