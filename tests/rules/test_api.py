from typing import List

import pytest

from .common import BaseTestRule


class TestApi(BaseTestRule):
    @pytest.fixture(params=[["gi_reo_gi_api = \"@@cacklecackle_gi_reo_gi@@\""]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "API"
