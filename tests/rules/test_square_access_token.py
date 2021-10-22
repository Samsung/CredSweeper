from typing import List

import pytest

from .common import BaseTestRule


class TestSquareAccessToken(BaseTestRule):
    @pytest.fixture(params=[["EAAAEEPtuW9FnP_CuCV-GIREOGIGIREOGIGIREOGIGIREOGIGIREOGIGIREOGIGI"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Square Access Token"
