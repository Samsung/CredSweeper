from typing import List

import pytest

from .common import BaseTestMultiRule, BaseTestRule


class TestGoogleMulti(BaseTestRule, BaseTestMultiRule):

    @pytest.fixture(
        params=[["012-GiReoGiGiReoGiGiReoGiGiReoGi1230.apps.googleusercontent.com\n", "4L2QMyTm6Rr0o46ytGiReoG1"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Google Multi"
