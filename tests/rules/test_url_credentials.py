from typing import List

import pytest

from .common import BaseTestRule


class TestUrlCredentials(BaseTestRule):

    @pytest.fixture(params=[
        ["https://user:pass12AB@your.domain.com/path"],  #
        ["url='https://user:pass12AB@your.domain.com/path'"]
    ])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "URL Credentials"
