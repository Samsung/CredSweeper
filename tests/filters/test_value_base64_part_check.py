import re
import unittest

from credsweeper.credentials import LineData
from credsweeper.filters import ValueBase64PartCheck
from tests.filters.conftest import DUMMY_ANALYSIS_TARGET


class TestValueBase64PartCheck(unittest.TestCase):

    def test_value_check_n(self) -> None:
        for prefix, value, suffix in [
            ("fp: zza0dxVlt0/", "TijfkIXPhSdtdakk9G", "\\nCIpPqrtaOxOx0sEXzS/MuYT4rE3363cXp1yCxqF3dhUP"),
            ("sha512-eGuFFw7Upda+g4p+QHvnW0RyTX/SVeJBDM/", "gCtMARO0cLuT2HcEKnTPvhjV6aGeqrCB", "/sbNop0Kszm0jsaWU4A=="),
                # left and right boundaries
            ("qcE81rS+FJHGy7KedoQ4juvg3FZ9lz4T/", "EAACEb00Kse0BAlGy7KeQ5YnaCEd09Eo",
             "+se0cBAlGy7KeQ5Yna9CoDsup39tiYdoQ4jH9Coup39tiYdWoQ4jHFZD"),
                # only left
            ("qcE81rS+FJHGy7KedoQ4juvg3FZ9lz4T/", "EAACEb00Kse0BAlGy7KeQ5YnaCEd09Eo", ""),
                # only right
            ("", "EAACEb00Kse0BAlGy7KeQ5YnaCEd09Eo", "/qcE81rS+FJHGy7KedoQ4juvg3FZ9lz4T"),
            ("hj4Ov3rIwAAdHIIAC7ARR4daWuDXZoA41Bk6QJC\\nLwgikiCrNulUp0VYmrLoEE/", "sBY3YlVbQdYgS9ulYJcKyInd8hWQ31TG",
             "/SSyz1SRd\\ncp8SD9bAu8SbqX4DWa6tV2XxopsabwQgWqGtJWzYIyuVFvdSuXGaZ"),
            ("aWrnS3VQGR0j4mLkKC1NUeljjA77zYyhVbIE0dR%2By7fmaHq7U%2BdegXWGpAZ+/", "4pR32luBFTAtWgUcCv56",
             "/p5y30X87Yz1khTIycdgpUW9kY7WdsC9zxoXTvMvWuVV98YyMnSGH2SYE5pwALBIr9QKi"),
            ("04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTlwIj+", "GgzlFDwPikM5vUkIT2WOtQxKWceQ4wzV",
             "/p9Y0jfEpUq6XHZIlai1oYHbDtx2Nc1k3z7"),
            ("GuBdjqFPQXaaOcxuJ5oLRDC7IxtkpNz1P9CByI/", "eEZQFtJDUtShrP0tTC",
             "\\nztg1zgkXhaz7IMxm4SgeuOUFy4mEcAGjQxs7qays"),
            ("sha512-eGuFFw7Upda+g4p+QHvnW0RyTX/SVeJBDM/", "gCtMARO0cLuT2HcEKnTPvhjV6aGeqrCB", "/sbNop0Kszm0jsaWU4A=="),
            ("sha512-eGuFFw7Upda+g4p+QHvnW0RyTX/SVeJBDM/", "gCtMARO0cLuT2HcEKnTPvhjV6aGeqrCB", "/sbNop0Kszm0jsaWU4A=="),
            ("<DP>FklyR1uZ/", "wPJjj611cdBcztlPdqoxssQGnh85BzCj",
             "/u3WqBpE2vjvyyvyI5kX6zk7S0ljKtt2jny2+00VsBerQ==</DP>"),
            ("sha512-h7fJ/", "5uWuRVyOtkO45pnt1Ih40CEleeyCHzipqAZO2e5H20g25Y48uYnFUiShvY4rZWNJ", "/Bib/KVPmanaCtOhA=="),
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

    def test_value_check_p(self) -> None:
        for prefix, value, suffix in [
            (" http://localhost:8888/v1/api/get?token=", "zUkITxodk63bDVUMwIymb3zKTxICz85zC00cv0Geline80", ""),
            ("http://example.com/api/v3/", "T1029384756B102984756", ""),
                # part of jwt
            ("04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTlwIj.", "GgzlFDwPikM5vUkIT2WOtQxKWceQ4wzV",
             ".p9Y0jfEpUq6XHZIlai1oYHbDtx2Nc1k3z7"),
            ("https://yourInstance.salesforce.com/services/Soap/m/{version}/", "00Dx0000006Y0xy", "")
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
            self.assertFalse(ValueBase64PartCheck().run(line_data, DUMMY_ANALYSIS_TARGET), line)
