from typing import List

import pytest

from .common import BaseTestRule


class TestAwsMwsKey(BaseTestRule):

    @pytest.fixture(params=[["AWS_MWS_KEY = \"amzn.mws.abcaef12-1231-5671-1231-abadea123156\"\n"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "AWS MWS Key"
