from typing import List

import pytest

from .common import BaseTestRule


class TestPayPalKey(BaseTestRule):

    @pytest.fixture(params=[["access_token$production$gireogi121451781$abcaeaabadef01134517891121451781"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "PayPal Braintree Access Token"
