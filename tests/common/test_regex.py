import pytest
from regex import regex


class TestRegex:
    TEST_AWS_ID = "ASIA0123456789ABCDEF"
    TEST_AWS_REGEX = regex.compile("(^|[^0-9A-Za-z])(?P<value>(AKIA|ASIA)[0-9A-Z]{16,17})([^0-9A-Za-z]|$)")

    @pytest.mark.parametrize(  #
        'text',  #
        [  #
            f"{TEST_AWS_ID}XX",  # 22 symbols
            f"i{TEST_AWS_ID}",  #
            f"X{TEST_AWS_ID}",  #
            f"{TEST_AWS_ID[0:18]}",  #
            f"{TEST_AWS_ID[0:18]}x",  #
            f"{TEST_AWS_ID[0:18]}+",  #
            f"{TEST_AWS_ID[0:18]}/",  #
            f"{TEST_AWS_ID[1:19]}"  #
        ])
    def test_regex_n(self, text: str):
        assert TestRegex.TEST_AWS_REGEX.search(text) is None

    @pytest.mark.parametrize(  #
        'text',  #
        [  #
            f"{TEST_AWS_ID}",  #
            f"#@(-{TEST_AWS_ID})+*&^%$",  # obviously inside delimiters
            f"N={TEST_AWS_ID}",  #
            f"\"{TEST_AWS_ID}\"",  #
            f"{TEST_AWS_ID}/6/g'",  #
            f"={TEST_AWS_ID}%2F",  #
            f"sed 's/{TEST_AWS_ID}/6/g'",  #
            f"{TEST_AWS_ID}X",  # 21 symbols in ID
            f"--key {TEST_AWS_ID}X --help"  # 21 symbols in ID
        ])
    def test_regex_p(self, text: str):
        obtained = TestRegex.TEST_AWS_REGEX.search(text)
        assert obtained is not None
        found = False
        for i in obtained.groups():
            pos = i.find(TestRegex.TEST_AWS_ID)
            if -1 != pos and 0 == pos:
                found = True
                break
        assert found
