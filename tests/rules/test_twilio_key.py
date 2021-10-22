from typing import List

import pytest

from .common import BaseTestRule


class TestTwilioKey(BaseTestRule):
    @pytest.fixture(params=[["SKABCAEFabcaeaABADEAabadea12145178"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Twilio API Key"
