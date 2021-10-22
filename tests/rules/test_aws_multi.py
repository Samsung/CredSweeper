from typing import List

import pytest

from .common import BaseTestMultiRule, BaseTestRule


class TestAwsMulti(BaseTestRule, BaseTestMultiRule):
    @pytest.fixture(params=[[
        "\"AwsAccessKey\": \"AKIAGIREOGIAWSKEY123\",", "\"AwsSecretKey\": \"CrackleGiReoGi123CrackleGiReoGi123AWSkey\""
    ]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "AWS Multi"
