from typing import List

import pytest

from .common import BaseTestRule


class TestFirebasDomain(BaseTestRule):
    @pytest.fixture(params=[
        ["api-project-615509201590.firebaseio.com"],
        ["api-project-615509201590.firebaseapp.com"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Firebase Domain"
