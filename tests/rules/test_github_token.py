from typing import List

import pytest

from .common import BaseTestRule


class TestGithubToken(BaseTestRule):

    @pytest.fixture(params=[
        ["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"],  #
        ["ghu_yK9Kliqr8NDDnCmMAcxFJ6mwIguP5Z0tad19"],  #
        ["ghr_1B4a2e77838347a7E420ce178F2E7c6912E169246c34E1ccbF66C46812d16D5B1A9Dc86A1498"]  #
    ])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Github Token"
