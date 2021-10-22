from typing import List

import pytest

from .common import BaseTestRule


class TestGoogleApiKey(BaseTestRule):
    @pytest.fixture(params=[["AIzaGiReoGiCrackleCrackle12315618112315"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Google API Key"
