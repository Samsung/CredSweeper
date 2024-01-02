from typing import List

import pytest

from .common import BaseTestRule


class TestCertificate(BaseTestRule):

    @pytest.fixture(params=[  #
        ["tlsClientCert: 'caN0dGlyMXN501628f1l19CV+LOQne:+xmAclk=='"],  #
        ["oidc_ca_cert: Tp2hY3loIlAzZS5Lb53"]  #
    ])
    def lines(self, request) -> List[str]:
        return request.param

    @pytest.fixture(params=["", "keyword='hamming'"])
    def empty_line(self, request) -> List[str]:
        return request.param

    @pytest.fixture
    def rule_name(self) -> str:
        return "Certificate"
