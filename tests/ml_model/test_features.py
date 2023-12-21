from credsweeper.common.constants import Severity, KeywordPattern
from credsweeper.credentials import Candidate, LineData
from credsweeper.ml_model.features import RenyiEntropy, WordInSecret, WordInLine, WordInPath, HasHtmlTag, \
    PossibleComment, IsSecretNumeric
from credsweeper.utils import Util
from tests import AZ_STRING


def test_renyi_entropy_p():
    test_entropy = RenyiEntropy('hex', 0, norm=True)
    probabilities = test_entropy.get_probabilities(AZ_STRING)
    print(probabilities)
    assert len(probabilities) == 6
    expected_max = [0.12500001, 0.12500001, 0.12500001, 0.12500001, 0.37500001, 0.12500001]
    expected_min = [0.12499999, 0.12499999, 0.12499999, 0.12499999, 0.37499999, 0.12499999]
    for n in range(6):
        assert expected_max[n] > probabilities[n], f"probabilities[{n}]"
        assert probabilities[n] > expected_min[n], f"probabilities[{n}]"


def test_renyi_entropy_n():
    test_entropy = RenyiEntropy('hex', 0, norm=False)
    probabilities = test_entropy.get_probabilities(AZ_STRING)
    print(probabilities)
    assert len(probabilities) == 6
    expected_max = [0.024, 0.024, 0.024, 0.024, 0.07, 0.024]
    expected_min = [0.023, 0.023, 0.023, 0.023, 0.06, 0.023]
    for n in range(6):
        assert expected_max[n] > probabilities[n], f"probabilities[{n}]"
        assert probabilities[n] > expected_min[n], f"probabilities[{n}]"


def test_estimate_entropy_n():
    test_entropy = RenyiEntropy('hex', 0)
    assert test_entropy.estimate_entropy([]) == 0


def test_estimate_entropy_p():
    test_entropy = RenyiEntropy('hex', 0)
    probabilities = test_entropy.get_probabilities('9e107d9d372bb6826bd81d3542a419d6')
    assert test_entropy.estimate_entropy(probabilities) > 0


def test_word_in_secret_p():
    test = WordInSecret(["fox"])
    ld = LineData(config=None,
                  line="line",
                  line_pos=0,
                  line_num=1,
                  path="path",
                  file_type="type",
                  info="info",
                  pattern=KeywordPattern.get_keyword_pattern("password"))
    ld.value = AZ_STRING
    assert test.extract(Candidate([ld], [], "rule", Severity.MEDIUM, [], True))


def test_word_in_secret_n():
    test = WordInSecret([])
    ld = LineData(config=None,
                  line="line",
                  line_pos=0,
                  line_num=1,
                  path="path",
                  file_type="type",
                  info="info",
                  pattern=KeywordPattern.get_keyword_pattern("password"))
    ld.value = ""
    assert not test.extract(Candidate([ld], [], "rule", Severity.MEDIUM, [], True))


def test_word_in_line_n():
    test = WordInLine([])
    ld = LineData(config=None,
                  line="line",
                  line_pos=0,
                  line_num=1,
                  path="path",
                  file_type="type",
                  info="info",
                  pattern=KeywordPattern.get_keyword_pattern("password"))
    assert not test.extract(Candidate([ld], [], "rule", Severity.MEDIUM, [], True))


def test_word_in_path_n():
    test = WordInPath([])
    ld = LineData(config=None,
                  line="line",
                  line_pos=0,
                  line_num=1,
                  path="path",
                  file_type="type",
                  info="info",
                  pattern=KeywordPattern.get_keyword_pattern("password"))
    assert not test.extract(Candidate([ld], [], "rule", Severity.MEDIUM, [], True))


def test_has_html_tag_n():
    test = HasHtmlTag()
    ld = LineData(config=None,
                  line="line",
                  line_pos=0,
                  line_num=1,
                  path="path",
                  file_type="type",
                  info="info",
                  pattern=KeywordPattern.get_keyword_pattern("password"))
    assert not test.extract(Candidate([ld], [], "rule", Severity.MEDIUM, [], True))


def test_possible_comment_n():
    test = PossibleComment()
    ld = LineData(config=None,
                  line="line",
                  line_pos=0,
                  line_num=1,
                  path="path",
                  file_type="type",
                  info="info",
                  pattern=KeywordPattern.get_keyword_pattern("password"))
    assert not test.extract(Candidate([ld], [], "rule", Severity.MEDIUM, [], True))


def test_is_secret_numeric_n():
    test = IsSecretNumeric()
    ld = LineData(config=None,
                  line="line",
                  line_pos=0,
                  line_num=1,
                  path="path",
                  file_type="type",
                  info="info",
                  pattern=KeywordPattern.get_keyword_pattern("password"))
    ld.value = 'dummy'
    assert not test.extract(Candidate([ld], [], "rule", Severity.MEDIUM, [], True))
