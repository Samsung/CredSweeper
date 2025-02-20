import pytest

from credsweeper.common.keyword_pattern import KeywordPattern
from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.utils import Util


class TestKeywordPattern:

    @pytest.mark.parametrize("line", ["melon is 'banana'"])
    def test_separator_n(self, config: Config, file_path: pytest.fixture, line: str) -> None:
        pattern = KeywordPattern.get_keyword_pattern("melon")
        line_data = LineData(config,
                             line,
                             0,
                             1,
                             file_path,
                             Util.get_extension(file_path),
                             info="dummy",
                             pattern=pattern)
        assert line_data.value is None

    @pytest.mark.parametrize("line", ["melon = 'banAna'", "melon : 'banAna'", "melon := 'banAna'"])
    def test_separator_p(self, config: Config, file_path: pytest.fixture, line: str) -> None:
        pattern = KeywordPattern.get_keyword_pattern("melon")
        line_data = LineData(config,
                             line,
                             0,
                             1,
                             file_path,
                             Util.get_extension(file_path),
                             info="dummy",
                             pattern=pattern)
        assert line_data.value == "banAna"

    @pytest.mark.parametrize(
        "line, value",
        [
            # ['''...log=1;User ID=X3;password=Quantum42!\\""''', '''Quantum42!'''],  # todo
            # ["""password='\\\\'secret-1\\\\''""", """\\'secret-1\\'"""],  # todo
            # ['''password="\\"secret-2\\""''', '''\\"secret-2\\"'''],  # todo
            # ["""password=rb'\\'secret=1\\''""", """\\'secret=1\\'"""],  # todo
            # ['''password=f"\\"secret=2\\""''', '''\\"secret=2\\"'''],  # todo
            # ['''password=r"\\\\"secret=3\\\\""''', '''\\"secret=3\\"'''],  # todo
            # ['''"password = 'sec;$2`\\'[\\/*;ret';";''', '''sec;$2`\\'[\\/*;ret'''],  # todo
            ['''"$password = "10qoakxncnfh47t_''', '''10qoakxncnfh47t_'''],  #
            [
                '''copes\":[\"user\"],\"note\":\"Note\",\"password\":\"cc6323cb2223f82f01\",\"upd_at\":\"1765....\",''',
                '''cc6323cb2223f82f01'''
            ],  #
            ['''"password = pas:sword # comment''', '''pas:sword'''],
            ['''x.password=pK5C4tlA/w1cO\\=\\=''', '''pK5C4tlA/w1cO\\=\\='''],  #
            ['''final String body = \"{ \\"passwords\\":\\"i0sEcReT\\\\/MwX3X\\","''', '''i0sEcReT\\\\/MwX3X'''],
            [
                '''\\\"password\\\"=\\u0026gt;\t\\n\\t\\\"lfFTfDT1roc4YbG9hy5cnvX\\n   oZ+Sc/wb+CvdF4s==\\\",\\n",''',
                '''lfFTfDT1roc4YbG9hy5cnvX\\n   oZ+Sc/wb+CvdF4s=='''
            ],
            [
                '''var request = {"password": "{\\"wks\\": \\"8x9s3ga7\\", \\"uzr\": \\"wbm\\"}","Any-Tail":"x\r"};''',
                '''{\\"wks\\": \\"8x9s3ga7\\", \\"uzr": \\"wbm\\"}'''
            ],
            ['''passwords: ["1029384756",''', '''1029384756'''],  #
            ['''passwords:[ "1029384756", "9801726354" ]''', '''1029384756'''],  #
            ['''password="\\"secret-line-wrap\\''', '''secret-line-wrap'''],  #
            ['''password=r"""secret4"""''', '''secret4'''],  #
            ['''password=r\\"\\"\\"secret5\\"\\"\\"''', '''secret5'''],  #
            ['''password="""secret6"""''', '''secret6'''],  #
            ['''password=\\\\"\\\\"\\\\"secret7\\\\"\\\\"\\\\"''', '''secret7'''],  #
            ['''password=\\\\"\\\\"\\\\"secret"7\\\\"\\\\"\\\\"''', '''secret"7'''],  #
            ['''password="""{\\"secret8\\"}"""''', '''{\\"secret8\\"}'''],  #
            ['''password="""secret'9"""''', '''secret'9'''],  #
            ["""password='''secret'6'''""", '''secret'6'''],  #
            ["""password='''secret`8'''""", '''secret`8'''],  #
            ["""password=``secret`7``""", '''secret`7'''],  #
            ["""password=``secret 5``""", '''secret 5'''],  #
            ["""password='secret\\ 5''""", '''secret\\ 5'''],  #
            ["""password=secret\\ 5""", '''secret\\ 5'''],  #
            ["""password=secret 0""", '''secret'''],  #
            ["""password=secret0\\""", '''secret0'''],  #
            ["""password=r'\\"secret\\"'""", '''\\"secret\\"'''],  #
            ['''password=r\\"{\\\\"secret\\\\"}\\"''', '{\\\\"secret\\\\"}'],  #
            ['''password=r"{\\"secret\\"}"''', '{\\"secret\\"}'],  #
            ["""password=b'"secret4"'""", '"secret4"'],  #
            ["""password=rb'\\\\"secret\\\\"'""", '\\\\"secret\\\\"'],  #
            ["""password=r\\'"sec'"'"'"ret"\\'""", '''"sec'"'"'"ret"'''],  #
            ["""\\'\\\\\\\\'password\\\\\\\\': b\\\\\\\\'secret\\\\\\\\'\\'""", "secret"],  #
            ["""'password': b'secret'""", """secret"""],  #
            ["""'password': r'secret'""", """secret"""],  #
            ["""'password': fr'secret'""", """secret"""],  #
            ["""\\'password\\': \\'secret\\'""", """secret"""],  #
            ['''db.setCred("{ \"password\" : \"" + SECRET + "\" }");''', ''' + SECRET + '''],
            ['''\\"password\\": \\"{\\\\"secret\\\\": \\\\"test\\\\"}\\"''', '{\\\\"secret\\\\": \\\\"test\\\\"}'],  #
            ['''"password": "{\\\\"secret\\\\": \\\\"test\\\\"}"''', '{\\\\"secret\\\\": \\\\"test\\\\"}'],  #
            # normal_str = "First line.\nSecond line.\nEnd of message.\n";
            ['''std::string password = R"multiline\\npassword";''', '''multiline\\npassword'''],  #
            ['''const wchar_t* password = L"wchar_t*secret";''', '''wchar_t*secret'''],  #
            ['''const char16_t* password = U"char16_t*secret";''', '''char16_t*secret'''],  #
            [
                '''char password[] = {'S', 'E', 'C', 'R', 'E', 'T', '\\0'};''',
                '''{'S', 'E', 'C', 'R', 'E', 'T', '\\0'}'''
            ],  #
            ['''"password": "{8vi6wL+10fI/eibC7wFwc}"''', '{8vi6wL+10fI/eibC7wFwc}'],  #
            ['''final String password = new String("SECRET") {''', '''SECRET'''],  #
            ['''final OAuth2AccessToken password = new OAuth2AccessToken(\"SEC.RET\");''', '''SEC.RET'''],  #
            ['''password = obfuscate(arg="SECRET") {''', '''SECRET'''],  #
            ['''final String password = new String(Super(Encrypted("SECRET"))) {''', '''SECRET'''],  #
            ['''final String password = new String(Super( Encrypted("SECRET", "dummy"))) {''', '''SECRET'''],  #
            ["""'password': 'ENC(lqjdoxlandicpfpqk)'""", """ENC(lqjdoxlandicpfpqk)"""],  #
            ["""'password': 'ENC[lqjdoxlandicpfpqk]'""", """ENC[lqjdoxlandicpfpqk]"""],  #
            ['''password24=secret42''', 'secret42'],  #
            ['''password24=secret42\\ ''', 'secret42\\ '],  #
            ['''password24=secret42\\''', 'secret42'],  #
            ['''password24=secret42\\n''', 'secret42'],  #
            ['password = 3VNdhWT3oFo5I7faffKO\\\neEagnK7tYBcGxhla\n;', '''3VNdhWT3oFo5I7faffKO'''],
            ['password = "3VNdhWT3oFo5I7faffKO\n   gnK7tYBcGxhla\n";', '''3VNdhWT3oFo5I7faffKO\n   gnK7tYBcGxhla\n'''],
            [
                "//&user%5Bemail%5D=credsweeper%40example.com&user%5Bpassword%5D=Dmdkesfdsq452%23%40!&user%5Bpassword_",
                "Dmdkesfdsq452%23%40!"
            ],
            ["password%3dDmsfdsq452!&user%5Bpassword_", "Dmsfdsq452!"],
            ["MY_TEST_PASSWORD={MY_TEST_PASSWORD}", "MY_TEST_PASSWORD"],
            ["MY_TEST_PASSWORD=(MY_TEST_PASSWORD)", "MY_TEST_PASSWORD"],
            ["MY_TEST_PASSWORD=<MY_TEST_PASSWORD>", "<MY_TEST_PASSWORD>"],  # <> are used in future to detect a template
            ["MY_TEST_PASSWORD=[MY_TEST_PASSWORD]", "MY_TEST_PASSWORD"],
            ["MY_TEST_PASSWORD=MY_TEST&PASSWORD!", "MY_TEST&PASSWORD!"],
            ["MY_TEST_PASSWORD='MY_TEST&PASSWORD!'", "MY_TEST&PASSWORD!"],
        ])
    def test_keyword_pattern_p(self, config: Config, file_path: pytest.fixture, line: str, value: str) -> None:
        pattern = KeywordPattern.get_keyword_pattern("password")
        line_data = LineData(config,
                             line,
                             0,
                             1,
                             file_path,
                             Util.get_extension(file_path),
                             info="dummy",
                             pattern=pattern)
        assert line_data.value == value

    @pytest.mark.parametrize("line", [
        "https://fonts.googleapis.com/css2?family=Montserrat:wght@500;700;900&family=Roboto:wght@300;400;500;700;900"
        "&family=Roboto+Mono:wght@300;400;600;900&display=swap"
    ])
    def test_keyword_pattern_n(self, config: Config, file_path: pytest.fixture, line: str) -> None:
        pattern = KeywordPattern.get_keyword_pattern("api")
        line_data = LineData(config, line, 0, 1, file_path, "file_type", "info", pattern)
        assert line_data.value is None
