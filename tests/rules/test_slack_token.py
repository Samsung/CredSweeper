from typing import List

import pytest

from .common import BaseTestRule


class TestSlackToken(BaseTestRule):

    @pytest.fixture(params=[["xoxa-FLYLIKEAGIREOGI-9d8cfc0f59"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Slack Token"
