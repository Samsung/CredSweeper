from typing import List

import pytest

from .common import BaseTestRule


class TestFacebookKey(BaseTestRule):
    @pytest.fixture(params=[["GI_REO_GI_FACEBOOK_TOKEN = \"EAACEdEose0cBAAaBbCcDdEeCrackle\""]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Facebook Access Token"
