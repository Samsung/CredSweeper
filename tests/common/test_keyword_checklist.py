from unittest import TestCase
from unittest.mock import patch

from credsweeper.common import KeywordChecklist
from credsweeper.utils import Util
from tests import AZ_STRING


class TestKeywordChecklist(TestCase):

    def test_keyword_checklist_p(self):
        with patch.object(Util, Util.read_file.__name__) as mock_read:
            mock_read.return_value = ["abcd", AZ_STRING, "1234"]
            keyword_checklist = KeywordChecklist().get_list()
            keyword_checklist.sort()
            self.assertEqual(["1234", AZ_STRING, "abcd"], keyword_checklist)

    def test_keyword_checklist_n(self):
        with patch.object(Util, Util.read_file.__name__) as mock_read:
            mock_read.return_value = ["", "1", "12", "12", "AZ", "az"]
            keyword_checklist = KeywordChecklist().get_list()
            self.assertEqual([], keyword_checklist)
