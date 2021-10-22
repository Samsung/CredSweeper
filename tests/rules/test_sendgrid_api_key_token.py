from typing import List

import pytest

from .common import BaseTestRule


class TestSendGridApiKey(BaseTestRule):
    @pytest.fixture(params=[["SG.gireogigireogigi.gireogigireogigi"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "SendGrid API Key"
