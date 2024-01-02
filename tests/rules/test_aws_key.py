from typing import List

import pytest

from .common import BaseTestRule


class TestAwsKey(BaseTestRule):

    @pytest.fixture(params=[["\"AwsAccessKey\": \"AKIAGIREOGIAWSKEY123\","]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "AWS Client ID"
