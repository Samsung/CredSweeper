from typing import List

import pytest

from .common import BaseTestRule


class TestAuth(BaseTestRule):
    @pytest.fixture(params=[["oauth_nonce: '1gZG4eh6qR6Ul2pqbKc5PwKjNlKadCwW7VW4uSyi9',"], ["authold = 'gigigi'"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture(params=["", "author='bob'"])
    def empty_line(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Auth"
