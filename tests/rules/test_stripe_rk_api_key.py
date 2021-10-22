from typing import List

import pytest

from .common import BaseTestRule


class TestStripeRestrictedApiKey(BaseTestRule):
    @pytest.fixture(params=[["rk_live_GIREOGICRACKLE1231167190"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Stripe Restricted API Key"
