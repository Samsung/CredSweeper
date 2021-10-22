from typing import List

import pytest

from .common import BaseTestRule


class TestShopifyToken(BaseTestRule):
    @pytest.fixture(params=[["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"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Shopify Token"
