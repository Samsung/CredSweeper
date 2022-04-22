from typing import List

import pytest

from .common import BaseTestRule


class TestMailGunKey(BaseTestRule):

    @pytest.fixture(params=[["key-GiReoGiCrackleGiReoGiCrackle1231"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "MailGun API Key"
