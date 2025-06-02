import base64
import unittest

from credsweeper.filters.value_json_web_key_check import ValueJsonWebKeyCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueJsonWebKeyCheck(unittest.TestCase):

    def test_value_jwk_check_n(self):
        self.assertTrue(ValueJsonWebKeyCheck().run(get_line_data(line=".", pattern=LINE_VALUE_PATTERN),
                                                   DUMMY_ANALYSIS_TARGET))
        self.assertTrue(ValueJsonWebKeyCheck().run(get_line_data(line="eyJungle", pattern=LINE_VALUE_PATTERN),
                                                   DUMMY_ANALYSIS_TARGET))
        self.assertTrue(ValueJsonWebKeyCheck().run(
            get_line_data(line="eyJ1234567890qwertyu#@$^$^&iopasdfghjklzxc", pattern=LINE_VALUE_PATTERN),
            DUMMY_ANALYSIS_TARGET))
        self.assertTrue(ValueJsonWebKeyCheck().run(
            get_line_data(line=base64.b64encode(b'{"kty": "oct","x": "WrMwQfoNaHTgXU5fZvRGAD"}').decode(),
                          pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))

    def test_value_jwt_check_p(self):
        self.assertFalse(ValueJsonWebKeyCheck().run(
            get_line_data(line=base64.b64encode(b'{"kty": "oct","k": "WrMwQfoNaHTgXU5fZvRGAD"}').decode(),
                          pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))
