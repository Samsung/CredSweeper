import re
import unittest

from credsweeper.credentials import LineData
from credsweeper.filters import ValueBase64KeyCheck
from tests.filters.conftest import DUMMY_ANALYSIS_TARGET


class TestValueBase64KeyCheck(unittest.TestCase):
    ALL_LINE_PATTERN = re.compile(
        r"(?P<value>\bMII[A-Za-f][0-9A-Za-z/+]{8}(?s:[^!#$&()*\-.:;<=>?@\[\]^_{|}~]{8,8000}))")

    def test_value_check_n(self) -> None:
        line_data = LineData(config=None,
                             path="dummy",
                             file_type="",
                             line="MIIXXXXX",
                             info="",
                             line_num=1,
                             line_pos=0,
                             pattern=TestValueBase64KeyCheck.ALL_LINE_PATTERN)
        self.assertTrue(ValueBase64KeyCheck().run(line_data, DUMMY_ANALYSIS_TARGET))

    def test_value_check_p(self) -> None:
        line = ("'''MIICXAIBAAKBgQDFgQqUYexFziVtw\\n\\rnEz9XaYjmGdpGVWAqL1NX41LIxRAy1tbo1hCBUppqWGfn"
                "\nWHwZE5k4sYt5cE6n4hcdEPj9kdrDaeF7Te9JZg1eDE9RwWColxC+5neCBCmQY2LmWJa6+HDgDKq+DJIpx8PCDb"
                "+i3oeOwHn00H/4T9JczK/XJzhQIDAQABAoGBALbGxu2u"
                "+aNYNZcv/Odi4FAqY/gprYY9hmV7DcNT6L8IO8AsMTZ87mjPShv/Z"
                "/Esl6M7Adzr+hyYjgWReTH3o6qMBdHyJhU28Ngsrt8EIaSYpE"
                "/O 2 h d p 6 l Z vSWVt/KD+HJMRIDVqj39DphuU8f0cqJkpLoP5xcetOH"
                "       /XVnIVQXm5AkEA4gc5HjeggbJkj4bJg/ROmKlLgMKalg0LS7Z3"
                "\tYXIhIGJcwE27ERB5DjqMJp38Yvz8WqUchNFqF4fxSEYTWVIiMwJBAN"
                "\t\t\t+xiNpJtX3qWI4T5iOQM7pE8Ngx+olpOpZkwQ6jBzNyTfaZZT\""
                "XpmvzvBZKWgkvxAE3BaeHjuXKlRYp7dVTXi2cCQEeKL7rvsl66nveKmueoAO \\\\"
                "\nRy2RH1Bkat9EBPjXOLUw7T8zVupOHey+IEB+4FHSgb"
                "\r\n\tmKf8EI29Vo4CGg1dGKyxwV8CQAqZ/"
                "\r   WRrDeDz1FKXetbApNL1JXz5kWglxpMOH2A0NckoZ62CQ5u0gJXwNhFmdLJor5z"
                "/x6bfBhD66DrR8xOcS40CQBoGNvyzjHXUdx64Yxmtz2FXq0fYI8J8ChgNfTe6l6d1nzEQ7i0SspM45L"
                "/n5tgyrBBGcqzQ/WBL1C8Ny5K+RxY='''\n  -----END")
        line_data = LineData(config=None,
                             path="dummy",
                             file_type="",
                             line=line,
                             info="",
                             line_num=1,
                             line_pos=0,
                             pattern=TestValueBase64KeyCheck.ALL_LINE_PATTERN)
        self.assertFalse(ValueBase64KeyCheck().run(line_data, DUMMY_ANALYSIS_TARGET))
