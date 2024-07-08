from typing import List

import pytest

from .common import BaseTestRule


class TestFacebookKey(BaseTestRule):

    @pytest.fixture(params=[[
        'FACEBOOK_T0KEN = '
        '"EAACEb00Kse0BAlGy7KeQ5YnaCEd09Eose0cBAlGy7KeQ5Yna9CoDsup39tiYdoQ4jH9Coup39tiYdWoQ4jHFZD"'
    ]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Facebook Access Token"
