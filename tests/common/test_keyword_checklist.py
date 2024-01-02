from unittest import TestCase

from credsweeper.common import KeywordChecklist
from credsweeper.utils import Util


class TestKeywordChecklist(TestCase):

    def test_keyword_set_p(self):
        # quick test to match all keywords for regex
        for i in KeywordChecklist().keyword_set:
            self.assertLessEqual(3, len(i))
            self.assertRegex(i, r"[a-z0-9.]{3,500}")

    def test_morpheme_set_p(self):
        # quick test to match all morphemes for regex
        for i in KeywordChecklist().morpheme_set:
            self.assertLessEqual(3, len(i))
            # valid symbols for variable names
            self.assertRegex(i, r"[a-z0-9_]{3,500}")

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

    def test_morpheme_set_n(self):
        # check whether the morphemes are optimized and updates the file with optimized list
        morpheme_checklist_data = Util.read_data(KeywordChecklist.MORPHEME_PATH)
        original_morpheme_list = morpheme_checklist_data.decode().split()
        original_morpheme_list_len = len(original_morpheme_list)
        morpheme_set = set(original_morpheme_list)
        optimized_morpheme_list = sorted(list(morpheme_set), key=lambda e: len(e))

        is_optimized = False
        while not is_optimized:
            morphemes_to_remove_set = set()
            optimized_morpheme_list_len = len(optimized_morpheme_list)
            idx = 0
            for optimized_morpheme in optimized_morpheme_list:
                idx += 1
                if optimized_morpheme.lower() == optimized_morpheme and 3 <= len(optimized_morpheme):
                    # search in rest list whether the items have the substring
                    local_idx = idx
                    while local_idx < optimized_morpheme_list_len:
                        if optimized_morpheme in optimized_morpheme_list[local_idx]:
                            # longer morpheme should be removed because it includes short morpheme inside
                            morphemes_to_remove_set.add(optimized_morpheme_list[local_idx])
                        local_idx += 1
                else:
                    # wrong - must be removed
                    morphemes_to_remove_set.add(optimized_morpheme)
            for to_remove in morphemes_to_remove_set:
                optimized_morpheme_list.remove(to_remove)
            is_optimized = 0 == len(morphemes_to_remove_set)
        diff = original_morpheme_list_len - len(optimized_morpheme_list)
        if diff:
            with open(KeywordChecklist.MORPHEME_PATH, "w") as f:
                # use alphabet sorting to keep constant order and reduce git diff
                text = '\n'.join(sorted(optimized_morpheme_list))
                f.write(text)
                f.write('\n')
        self.assertEqual(0, diff, "Morpheme list has been rearranged and updated")
