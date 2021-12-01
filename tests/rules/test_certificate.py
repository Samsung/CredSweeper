from typing import List

import pytest

from .common import BaseTestRule


class TestCertificate(BaseTestRule):
    @pytest.fixture(params=[["tlsClientCert: 'ckN0dGlyMXN503YNfjTcf9CV+GGQneN+xmAclQ=='"]])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture(params=["", "keyword='hamming'"])
    def empty_line(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Certificate"
