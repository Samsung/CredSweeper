from typing import List

import pytest

from .common import BaseTestRule


class TestHerokuApiKey(BaseTestRule):
    @pytest.fixture(params=[["HerOkU1212121d-A147-b252-12121212121c"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Heroku API Key"
