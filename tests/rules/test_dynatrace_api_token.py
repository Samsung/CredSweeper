from typing import List

import pytest

from .common import BaseTestRule


class TestStripeApiKey(BaseTestRule):
    # Example from official site
    # https://www.dynatrace.com/support/help/dynatrace-api/basics/dynatrace-api-authentication/
    @pytest.fixture(
        params=[["dt0c01.ST2EY72KQINMH574WMNVI7YN.G3DFPBEJYMODIDAEX454M7YWBUVEFOWKPRVMWFASS64NFH52PX6BNDVFFM572RZM"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Dynatrace API Token"
