from typing import List

import pytest

from .common import BaseTestRule


class TestKey(BaseTestRule):

    @pytest.fixture(params=[["hmac_key = 'zdosafhzwhpelghs';"], ["keydocker = 'gigigi'"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture(params=["", "keyword='hamming'"])
    def empty_line(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Key"
