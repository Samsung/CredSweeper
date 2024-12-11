import re
import unittest

from credsweeper.credentials import LineData
from credsweeper.filters import ValueBase64PartCheck
from tests.filters.conftest import DUMMY_ANALYSIS_TARGET


class TestValueBase64PartCheck(unittest.TestCase):
    EAA_PATTERN = re.compile(r"(?P<value>\bEAA[0-9A-Za-z]+\b)")

    def test_value_check_n(self) -> None:
        for line in [
                # left and right boundaries
                "qcE81rS+FJHGy7KedoQ4juvg3FZ9lz4T/"
                "EAACEb00Kse0BAlGy7KeQ5YnaCEd09Eo"
                "+se0cBAlGy7KeQ5Yna9CoDsup39tiYdoQ4jH9Coup39tiYdWoQ4jHFZD",
                # only left
                "qcE81rS+FJHGy7KedoQ4juvg3FZ9lz4T/"
                "EAACEb00Kse0BAlGy7KeQ5YnaCEd09Eo",
                # only right
                "EAACEb00Kse0BAlGy7KeQ5YnaCEd09Eo"
                "/qcE81rS+FJHGy7KedoQ4juvg3FZ9lz4T"
        ]:
            line_data = LineData(config=None,
                                 path="dummy",
                                 file_type="",
                                 line=line,
                                 info="",
                                 line_num=1,
                                 line_pos=0,
                                 pattern=TestValueBase64PartCheck.EAA_PATTERN)
            self.assertTrue(ValueBase64PartCheck().run(line_data, DUMMY_ANALYSIS_TARGET), line)

    def test_value_check_p(self) -> None:
        for line in ["http://meta.test/api/EAACRvAWiwzR8rcXFsLiUH13ybj0tdEa?"]:
            line_data = LineData(config=None,
                                 path="dummy",
                                 file_type="",
                                 line=line,
                                 info="",
                                 line_num=1,
                                 line_pos=0,
                                 pattern=TestValueBase64PartCheck.EAA_PATTERN)
            self.assertFalse(ValueBase64PartCheck().run(line_data, DUMMY_ANALYSIS_TARGET), line)

    def test_value_jwt_part_p(self) -> None:
        value = "GgzlFDwPikM5vUkIT2WOtQxKWceQ4wzV"
        line = f"04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTlwIj.{value}.p9Y0jfEpUq6XHZIlai1oYHbDtx2Nc1k3z7"
        line_data = LineData(config=None,
                             path="dummy",
                             file_type="",
                             line=line,
                             info="",
                             line_num=1,
                             line_pos=0,
                             pattern=re.compile(fr"(?P<value>{value})"))
        self.assertFalse(ValueBase64PartCheck().run(line_data, DUMMY_ANALYSIS_TARGET), line)

    def test_value_base64_part_n(self) -> None:
        for prefix, value, suffix in [
            ("GuBdjqFPQXaaOcxuJ5oLRDC7IxtkpNz1P9CByI/", "eEZQFtJDUtShrP0tTC",
             "\\nztg1zgkXhaz7IMxm4SgeuOUFy4mEcAGjQxs7qays"),
            ("hj4Ov3rIwAAdHIIAC7ARR4daWuDXZoA41Bk6QJC\\nLwgikiCrNulUp0VYmrLoEE/", "sBY3YlVbQdYgS9ulYJcKyInd8hWQ31TG",
             "/SSyz1SRd\\ncp8SD9bAu8SbqX4DWa6tV2XxopsabwQgWqGtJWzYIyuVFvdSuXGaZ"),
            ("aWrnS3VQGR0j4mLkKC1NUeljjA77zYyhVbIE0dR%2By7fmaHq7U%2BdegXWGpAZ+/", "4pR32luBFTAtWgUcCv56",
             "/p5y30X87Yz1khTIycdgpUW9kY7WdsC9zxoXTvMvWuVV98YyMnSGH2SYE5pwALBIr9QKi"),
            ("04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTlwIj+", "GgzlFDwPikM5vUkIT2WOtQxKWceQ4wzV",
             "/p9Y0jfEpUq6XHZIlai1oYHbDtx2Nc1k3z7"),
                # ("sha512-PsjRC7REiu/", "xbYcsFHSp5oKpFNnsj", "/52OVb4zPTRK5onXwVF3=="),
        ]:
            line = ''.join([prefix, value, suffix])
            line_data = LineData(config=None,
                                 path="dummy",
                                 file_type="",
                                 line=line,
                                 info="",
                                 line_num=1,
                                 line_pos=0,
                                 pattern=re.compile(fr"(?P<value>{value})"))
            self.assertTrue(ValueBase64PartCheck().run(line_data, DUMMY_ANALYSIS_TARGET), line)
