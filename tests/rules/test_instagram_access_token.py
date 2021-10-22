import random
import string
from typing import List

import pytest

from .common import BaseTestRule


class TestInstagramAccessToken(BaseTestRule):
    @pytest.fixture(
        params=[["IGQVJ" + ''.join(random.choice(string.ascii_letters + string.digits) for i in range(157))]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Instagram Access Token"
