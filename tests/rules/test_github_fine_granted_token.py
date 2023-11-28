from typing import List

import pytest

from .common import BaseTestRule


class TestGithubFineGrantedToken(BaseTestRule):

    @pytest.fixture(params=[
        ["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Q"],  #
    ])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Github Fine-granted Token"
