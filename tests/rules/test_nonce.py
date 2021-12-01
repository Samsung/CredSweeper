from typing import List

import pytest

from .common import BaseTestRule


class TestNone(BaseTestRule):
    @pytest.fixture(params=[["nonce = '1053604598'"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture(params=["", "keyword='hamming'"])
    def empty_line(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Nonce"
