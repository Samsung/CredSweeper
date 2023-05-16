from unittest import TestCase

from credsweeper.common import KeywordChecklist
from credsweeper.utils import Util


class TestKeywordChecklist(TestCase):

    def test_keyword_set_p(self):
        # quick test to match all keywords for regex
        for i in KeywordChecklist().keyword_set:
            self.assertLessEqual(3, len(i))
            self.assertRegex(i, r"[a-z0-9.]{3,500}")

    def test_keyword_set_n(self):
        # checks whether the keywords are unique, in lower case and not shorter than 3 symbols
        keyword_checklist_bytes = Util.read_data(KeywordChecklist.KEYWORD_PATH)
        keyword_set = set(keyword_checklist_bytes.decode().split())
        new_set = set()
        wrong_items = []
        for i in keyword_set:
            if i.lower() == i and 3 <= len(i):
                new_set.add(i)
            else:
                wrong_items.append(i)
        if wrong_items:
            # writes correct checklist to output file - it must be applied
            with open(KeywordChecklist.KEYWORD_PATH, "w") as f:
                # use alphabet sorting to keep constant order and reduce git diff
                text = '\n'.join(sorted(list(new_set)))
                f.write(text)
                f.write('\n')
        self.assertFalse(wrong_items, "Keywords list has been rearranged and updated")
