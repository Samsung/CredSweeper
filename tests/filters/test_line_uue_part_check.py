from unittest import TestCase

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.line_uue_part_check import LineUUEPartCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_DESCRIPTOR
from tests.test_utils.dummy_line_data import get_line_data


class TestLineUUEPartCheck(TestCase):

    def test_line_uue_part_check_short_n(self):
        line = """#````"""
        cred_candidate = get_line_data(line=line, pattern=LINE_VALUE_PATTERN)
        target = AnalysisTarget(line_pos=0, lines=[line, line], line_nums=[1, 2], descriptor=DUMMY_DESCRIPTOR)
        self.assertFalse(LineUUEPartCheck().run(cred_candidate, target))

    def test_line_uue_part_check_uue__n(self):
        line = """M[@%]PW:2Z.Q?2M^S;`4G?E0C.@V&?0KY]]"H3Y@6$#I4V*R^"+B,2P6`A)UL"""
        cred_candidate = get_line_data(line=line, pattern=LINE_VALUE_PATTERN)
        cred_candidate.line_pos = 1
        target = AnalysisTarget(line_pos=1,
                                lines=["begin 644 x3wo.bin", line, "#````", "`", "end"],
                                line_nums=[1, 2, 3, 4, 5],
                                descriptor=DUMMY_DESCRIPTOR)
        self.assertFalse(LineUUEPartCheck().run(cred_candidate, target))

    def test_line_uue_part_single_n(self):
        line = """M[@%]PW:2Z.Q?2M^S;`4G?E0C.@V&?0KY]]"H3Y@6$#I4V*R^"+B,2P6`A)UL"""
        cred_candidate = get_line_data(line=line, pattern=LINE_VALUE_PATTERN)
        target = AnalysisTarget(line_pos=0, lines=[line], line_nums=[1], descriptor=DUMMY_DESCRIPTOR)
        self.assertFalse(LineUUEPartCheck().run(cred_candidate, target))

    def test_line_uue_part_check_n(self):
        line = """M[@%]PW:2Z.Q?2M^S;`4G?E0C.@V&?0KY]]"H3Y@6$#I4V*R^"D+lowercase"""
        cred_candidate = get_line_data(line=line, pattern=LINE_VALUE_PATTERN)
        target = AnalysisTarget(line_pos=0, lines=[line, line], line_nums=[1, 2], descriptor=DUMMY_DESCRIPTOR)
        self.assertFalse(LineUUEPartCheck().run(cred_candidate, target))

    def test_line_uue_part_check_p(self):
        line = """M[@%]PW:2Z.Q?2M^S;`4G?E0C.@V&?0KY]]"H3Y@6$#I4V*R^"+B,2P6`A)UL"""
        cred_candidate = get_line_data(line=line, pattern=LINE_VALUE_PATTERN)
        target = AnalysisTarget(line_pos=0, lines=[line, line], line_nums=[1, 2], descriptor=DUMMY_DESCRIPTOR)
        self.assertTrue(LineUUEPartCheck().run(cred_candidate, target))
        # check for empty line
        cred_candidate.line = ''
        self.assertTrue(LineUUEPartCheck().run(cred_candidate, target))
