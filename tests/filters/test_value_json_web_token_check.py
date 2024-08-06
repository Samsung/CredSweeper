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

            get_line_data(line="eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5In0.eyJhdWQiOiJURVNUUyIsImV4cCI6MTg1OTEyMTI3NSwianRpIjoiWE5MWjZYWVBIVE1ESlFSTlFPSFVPSlFHV0NVN01JNVc1SlhDWk5YQllVS0VRVzY3STI1USIsImlhdCI6MTU0Mzc2MTI3NSwiaXNzIjoiT0NBVDMzTVRWVTJWVU9JTUdOR1VOWEo2NkFIMlJMU0RBRjNNVUJDWUFZNVFNSUw2NU5RTTZYUUciLCJuYW1lIjoiU3luYWRpYSBDb21tdW5pY2F0aW9ucyBJbmMuIiwibmJmIjoxNTQzNzYxMjc1LCJzdWIiOiJPQ0FUMzNNVFZVMlZVT0lNR05HVU5YSjY2QUgyUkxTREFGM01VQkNZQVk1UU1JTDY1TlFNNlhRRyIsInR5cGUiOiJvcGVyYXRvciIsIm5hdHMiOnsic2lnbmluZ19rZXlzIjpbIk9EU0tSN01ZRlFaNU1NQUo2RlBNRUVUQ1RFM1JJSE9GTFRZUEpSTUFWVk40T0xWMllZQU1IQ0FDIiwiT0RTS0FDU1JCV1A1MzdEWkRSVko2NTdKT0lHT1BPUTZLRzdUNEhONk9LNEY2SUVDR1hEQUhOUDIiLCJPRFNLSTM2TFpCNDRPWTVJVkNSNlA1MkZaSlpZTVlXWlZXTlVEVExFWjVUSzJQTjNPRU1SVEFCUiJdfX0.hyfz6E39BMUh0GLzovFfk3wT4OfualftjdJ_eYkLfPvu5tZubYQ_Pn9oFYGCV_6yKy3KMGhWGUCyCdHaPhalBw",
                          pattern=LINE_VALUE_PATTERN), DUMMY_ANALYSIS_TARGET))
