import unittest

from credsweeper.filters import ValueJsonWebTokenCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueJsonWebTokenCheck(unittest.TestCase):

    def test_value_jwt_check_p(self):
        self.assertTrue(ValueJsonWebTokenCheck().run(get_line_data(line=".", pattern=LINE_VALUE_PATTERN),
                                                     DUMMY_ANALYSIS_TARGET))
        self.assertTrue(ValueJsonWebTokenCheck().run(get_line_data(line="eyJungle", pattern=LINE_VALUE_PATTERN),
                                                     DUMMY_ANALYSIS_TARGET))
        self.assertTrue(ValueJsonWebTokenCheck().run(
            get_line_data(line="1234567890qwertyuiopasdfghjklzxc", pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))
        self.assertTrue(ValueJsonWebTokenCheck().run(
            get_line_data(line="eyJhbGciOiJSUzI1NiJ9Cg.eyJleHAiOjY1NTM2fQo.eyJleHAiOjY1NTM2fQo",
                          pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))
        self.assertTrue(ValueJsonWebTokenCheck().run(
            get_line_data(line="eyJhbGciOiJSUzI1NiJ9Cg.eyJleHAiOjY1NTM2fQo.AAAAAAAAAAAAAAAAAAAAAAA",
                          pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))
        self.assertTrue(ValueJsonWebTokenCheck().run(
            get_line_data(line="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.x3.GFsFyGiCUIP5VHI9CEJL9thWsGjSZf1fJfarNk-LGTM",
                          pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))

    def test_value_jwt_check_n(self):
        self.assertFalse(ValueJsonWebTokenCheck().run(
            get_line_data(line="eyJhbGciOiJQUzM4NCJ9.eyJkdW1teSI6bnVsbH0.eyJpc3MiOiJqb2UifQ." \
                               "_VP9ZxcPkOptWScOUMXriLH31bTcrg0YhlYL-A7TTHLX7LTDKjggtVq3Nmdl4GIS" \
                               "gJdM7GHHZOJHckUjgD-T3X6oHQanKqjpWjU-GxcnOkM86e0joZgJUL7CpHUt7e3W" \
                               "MhbUrOCyCFRrxOXtuTvGr2m_LdS7I5OyZ4xEP4JRcsOgOnGq-MEWmLqrRvc4zy5m" \
                               "pM6tJwJXI8fr1tF4pcAZxXR17ITCrocVSRC6NuWOVzh_XyyEVRUfqlDbJnU2Z_I0" \
                               "dfEQIcC6K5hAgQGSZQC_pQDA51RUoUHa9KfNskerI681fJ8mbjIlbf68CFdXZnjE" \
                               "zobUhMn5Z544PF9DjW1BVtsQgXtHlSDFxl6MIMVdvM8oLRbrjlf6BYCRnCxuTA_y" \
                               "Ui1o9ndy7ckISHQVhuYFKu78l7nqC4heghK_Gw4h7EB7s8eEuUC-D6JjVtX10IyS" \
                               "vCRkRo7f8dWQTjFLs7mlPowjRz0cP5J-MmCoegKHYagOHZ_ArXOR91_u8jMdwmOf",
                          pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))
        self.assertFalse(ValueJsonWebTokenCheck().run(
            get_line_data(line="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." \
                               "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." \
                               ".e30.GFsFyGiCUIP5VHI9CEJL9thWsGjSZf1fJfarNk-LGTM",
                          pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))
