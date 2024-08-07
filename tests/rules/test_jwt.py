from typing import List

import pytest

from .common import BaseTestRule


class TestJwt(BaseTestRule):

    @pytest.fixture(params=[[
        "jwt: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxN"
        "TE2MjM5MDIyLCJ0ZXN0IjoiSSBuZWVkIHJlYWxseSByZWFsbHkgbG9uZyBsb25nIGxvbmcgbG9uZyBsb25nIGxvbmcgbG9uZyBsb25nI"
        "GxvbmcgbG9uZyBsb25nIGxvbmcgbG9uZyBsb25nIGxvbmcgbG9uZyBsb25nIGxvbmcgbG9uZyBsb25nIGxvbmcgbG9uZyBsb25nIGxvb"
        "mcgbG9uZyBsb25nIGxvbmcgbG9uZyBsb25nIGxvbmcgbG9uZyBsb25nIGxvbmcgbG9uZyBsb25nIGxvbmcgbG9uZyBsb25nIGxvbmcgb"
        "G9uZyBsb25nIGxvbmcgbG9uZyBsb25nIGxvbmcgbG9uZyBsb25nIGxvbmcgbG9uZyBsb25nIGxvbmcgbG9uZyBsb25nIGxvbmcgbG9uZ"
        "yBsb25nIGxvbmcgbG9uZyBsb25nIGxvbmcgbG9uZyBqd3QgdG9rZW4ifQ.4pWgA4mthx4FPPh1AZQY0luTKTQ7VOj6PGwwiANvtqg'"
    ]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "JSON Web Token"
