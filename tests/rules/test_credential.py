from typing import List

import pytest

from .common import BaseTestRule


class TestCredential(BaseTestRule):
    @pytest.fixture(params=[["gi_reo_gi_credential = \"cracklecrackle\""]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Credential"
