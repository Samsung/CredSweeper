from regex import regex

from credsweeper.common.constants import Severity, Chars
from credsweeper.credentials import Candidate, LineData
from credsweeper.ml_model.features import RenyiEntropy, WordInSecret, WordInLine, WordInPath, HasHtmlTag, \
    PossibleComment, IsSecretNumeric
from credsweeper.utils import Util


def test_renyi_entropy_p():
    test_entropy = RenyiEntropy('hex', 0, norm=True)
    probabilities = test_entropy.get_probabilities('Quick brown fox jumps over the lazy dog')
    print(probabilities)
    assert len(probabilities) == 6
    expected_max = [0.14285715, 0.14285715, 0.14285715, 0.14285715, 0.28571430, 0.14285715]
    expected_min = [0.14285714, 0.14285713, 0.14285713, 0.14285713, 0.28571428, 0.14285713]
    for n in range(6):
        assert expected_max[n] > probabilities[n] > expected_min[n]


def test_renyi_entropy_n():
    test_entropy = RenyiEntropy('hex', 0, norm=False)
    probabilities = test_entropy.get_probabilities('Quick brown fox jumps over the lazy dog')
    print(probabilities)
    assert len(probabilities) == 6
    expected_max = [0.026, 0.026, 0.026, 0.026, 0.06, 0.026]
    expected_min = [0.024, 0.024, 0.024, 0.024, 0.04, 0.024]
    for n in range(6):
        assert expected_max[n] > probabilities[n] > expected_min[n]


def test_estimate_entropy_n():
    test_entropy = RenyiEntropy('hex', 0)
    assert test_entropy.estimate_entropy([]) == 0


def test_estimate_entropy_p():
    test_entropy = RenyiEntropy('hex', 0)
    probabilities = test_entropy.get_probabilities('9e107d9d372bb6826bd81d3542a419d6')
    assert test_entropy.estimate_entropy(probabilities) > 0


def test_word_in_secret_n():
    test = WordInSecret([])
    ld = LineData(config=None, line="line", line_num=1, path="path", pattern=Util.get_keyword_pattern("password"))
    assert not test.extract(Candidate([ld], [], "rule", Severity.MEDIUM, [], True))


def test_word_in_line_n():
    test = WordInLine([])
    ld = LineData(config=None, line="line", line_num=1, path="path", pattern=Util.get_keyword_pattern("password"))
    assert not test.extract(Candidate([ld], [], "rule", Severity.MEDIUM, [], True))


def test_word_in_path_n():
    test = WordInPath([])
    ld = LineData(config=None, line="line", line_num=1, path="path", pattern=Util.get_keyword_pattern("password"))
    assert not test.extract(Candidate([ld], [], "rule", Severity.MEDIUM, [], True))


def test_has_html_tag_n():
    test = HasHtmlTag()
    ld = LineData(config=None, line="line", line_num=1, path="path", pattern=Util.get_keyword_pattern("password"))
    assert not test.extract(Candidate([ld], [], "rule", Severity.MEDIUM, [], True))


def test_possible_comment_n():
    test = PossibleComment()
    ld = LineData(config=None, line="line", line_num=1, path="path", pattern=Util.get_keyword_pattern("password"))
    assert not test.extract(Candidate([ld], [], "rule", Severity.MEDIUM, [], True))


def test_is_secret_numeric_n():
    test = IsSecretNumeric()
    ld = LineData(config=None, line="line", line_num=1, path="path", pattern=Util.get_keyword_pattern("password"))
    ld.value = 'dummy'
    assert not test.extract(Candidate([ld], [], "rule", Severity.MEDIUM, [], True))
