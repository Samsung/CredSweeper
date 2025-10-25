from typing import List

import pytest

from .common import BaseTestMultiRule, BaseTestRule


class TestAwsMulti(BaseTestRule, BaseTestMultiRule):

    @pytest.fixture(params=[[
        "\"AwsAccessKey\": \"AKIAGIREOGIAWSKEY123\",", "\"AwsSecretKey\": \"exA3p1E42db9bbba8f7ea0f9e47b287de5fc7E57\""
    ]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "AWS Multi"
