import unittest

from credsweeper.filters import ValueJsonWebTokenCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueJsonWebTokenCheck(unittest.TestCase):

    def test_value_jwt_check_p(self):
        self.assertTrue(ValueJsonWebTokenCheck().run(get_line_data(line="", pattern=LINE_VALUE_PATTERN),
                                                     DUMMY_ANALYSIS_TARGET))
        self.assertTrue(ValueJsonWebTokenCheck().run(get_line_data(line="eyJungle", pattern=LINE_VALUE_PATTERN),
                                                     DUMMY_ANALYSIS_TARGET))
        self.assertTrue(ValueJsonWebTokenCheck().run(
            get_line_data(line="1234567890qwertyuiopasdfghjklzxc", pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))
        self.assertTrue(ValueJsonWebTokenCheck().run(
            get_line_data(line="eyJhbGciOiJSUzI1NiJ9Cg.eyJleHAiOjY1NTM2fQo.eyJleHAiOjY1NTM2fQo",
                          pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))
        self.assertTrue(ValueJsonWebTokenCheck().run(
            get_line_data(line="eyJhbGciOiJSUzI1NiJ9Cg.eyJleHAiOjY1NTM2fQo.65474687468446387653",
                          pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))

    def test_value_jwt_check_n(self):
        self.assertFalse(ValueJsonWebTokenCheck().run(
            get_line_data(line="eyJhbGciOiJQUzM4NCJ9.eyJpc3MiOiJqb2UifQ.mlPowjRz0cP5J-MmCoegKHYagOHZ_ArXOR91_u8jMdwmOfdfEQIcC6K5hAgQGSZQC_pQDA51RUoUHatsQgXtHlSDC_VP9ZxcPkOptWScOUMXriLH31bTcrg0YhlYL-A7TTHLMhbUrOCKqjpWjU-GxcnOkM86e0joZgJUL7CpHUtyCFRrxOXtuTvGr2m_LdS7I5OyZ4xEP4JRcsOgOnGq-m7e3WX7LTDKjggtVq3Nmdl4GISgJdM7GHHZOJHckUjgD-T3X6oHQanFdXZnjEl7nqo9KfN0skerI681fJ8mbjIlbf68pM6tJwJXI8fr1tF4pcAZxXR17ITCrocVSRC6NuWOVzh_XyyEVMEWmLqrRvc4zyRUfqlDbUhMn55Z54bJnU2Z_IzUi1o9ndy7ckISHQVhuYFKu789DjW1BV4PFFxC4heghK_Gw4h7El6MIMVdvM8oLRbrjlf6BYCRnCxuTA_y10IyB7s8eEuUC-D6JjVtXSvCRkRo7f8dWQTjFLs7",
                          pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))
