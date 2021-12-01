from typing import List

import pytest

from .common import BaseTestRule


class TestSalt(BaseTestRule):
    @pytest.fixture(params=[["salt_data = '^S4lt$'"], ["salt = '1L1SziaanR3sdPz51cHA'"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture(params=["", "keyword='hamming'"])
    def empty_line(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Salt"
