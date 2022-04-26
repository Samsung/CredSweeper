from typing import List

import pytest

from .common import BaseTestRule


class TestPyPiApiToken(BaseTestRule):

    @pytest.fixture(params=[
        [
            "pypi-AgEIcHlwaS5vcmc"  #
            "CJGE3ZjdlNzVmLTRhOGEtNGY1MC1iMzEwLWQzZTQ1NmJiYzMzMQ"  #
            "ACJXsicGVybWlzc2lvbnMiOiAidXNlciIsICJ2ZXJzaW9uIjogM"  #
            "X0AAAYgdUBLuCnfvl7n3ZIgLjCvIDuk9GQxDbw4PHxRUAwPvIk"  #
        ],
        [
            "pypi-AgENdGVzdC5weXB"  #
            "CJDc5ZThjYzc4LWViY2YtNGFiZS1iOTNiLTQ3ZWVjOGFmYjIxNQ"  #
            "ACJXsicGVybWlzc2lvbnMiOiAidXNlciIsICJ2ZXJzaW9uIjogM"  #
            "X0AAAYgNJxF-my_lC6DUayAYu3KhiASbVvQA8FLI7wo-OkXoLs"  #
        ]
    ])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "PyPi API Token"
