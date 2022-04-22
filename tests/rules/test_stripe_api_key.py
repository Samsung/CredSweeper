from typing import List

import pytest

from .common import BaseTestRule


class TestStripeApiKey(BaseTestRule):

    @pytest.fixture(params=[["sk_live_GIREOGICRACKLE1134517810"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Stripe Standard API Key"
