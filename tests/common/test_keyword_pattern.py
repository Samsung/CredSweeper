import pytest

from credsweeper.common.keyword_pattern import KeywordPattern
from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.utils.util import Util
from tests.filters.conftest import KEYWORD_PASSWORD_PATTERN


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
            # ["""password='\\\\'secret-1\\\\''""", """\\'secret-1\\'"""],  # todo
            # ['''password="\\"secret-2\\""''', '''\\"secret-2\\"'''],  # todo
            # ["""password=rb'\\'secret=1\\''""", """\\'secret=1\\'"""],  # todo
            # ['''password=f"\\"secret=2\\""''', '''\\"secret=2\\"'''],  # todo
            # ['''password=r"\\\\"secret=3\\\\""''', '''\\"secret=3\\"'''],  # todo
            # ['''"password = 'sec;$2`\\'[\\/*;ret';";''', '''sec;$2`\\'[\\/*;ret'''],  # todo
            ["deFINE \\n\\t('DB_PASSWORD',\\n\\t'devSeCrEt');", "devSeCrEt"],
            ['''...log=1;User ID=X3;password=Quantum42!\\""''', '''Quantum42!'''],
            [
                'Password: []byte{134, 217, 176, 23, 206, 245, 164, 94, 102, 114, 172, 33, 248, 215, 246, 357},',
                '134, 217, 176, 23, 206, 245, 164, 94, 102, 114, 172, 33, 248, 215, 246, 357'
            ],
            [
                'password = util.getPasswordFromHex("c275ecec7b5eda8a330bec5bc275b3f1", None)',
                "c275ecec7b5eda8a330bec5bc275b3f1"
            ],
            ['password = util.getPassword("User1", "D3fa9UL7Pa5s")', "D3fa9UL7Pa5s"],
            ['password = i[2].get("PASS", "D3fA9UL7Pa5s")', "D3fA9UL7Pa5s"],
            ['password = os.getenv("DB_PASS", "D3fA9Ul7pAs5")', "D3fA9Ul7pAs5"],
            ["password = data.get ( 'MY_PASS' , default = 'D3fA9Ul7pA5s' ) ", "D3fA9Ul7pA5s"],
            [
                'PASSWORD = bytes([0xDF, 0x42, 0xD8, 0x34, 0xDD, 0x1E, 0xD8, 0x24, 0xD8, 0x37, 0xD8, 0x01, 0xD8, 0x52])',
                "0xDF, 0x42, 0xD8, 0x34, 0xDD, 0x1E, 0xD8, 0x24, 0xD8, 0x37, 0xD8, 0x01, 0xD8, 0x52"
            ],
            ['password = superCrypto ( "CEKPET" ) ;', "CEKPET"],
            ['self.setPassword("0bead47f3c5bc275ec7b5eda8a333f")', "0bead47f3c5bc275ec7b5eda8a333f"],
            ['if str(password) == "0bead47f3c5bc275ec7b5eda8a333f":', "0bead47f3c5bc275ec7b5eda8a333f"],
            ['if [[ "%{password}" =~ "himmelsrand"  ]]; then', 'himmelsrand'],
            ["setPasssword ( 'MY_TEST&PASSWORD!',", "MY_TEST&PASSWORD!"],
            ["setPasssword('MY_TEST&PASSWORD!')", "MY_TEST&PASSWORD!"],
            ['#define password {0x35, 0x34, 0x65, 0x9b, 0x1c, 0x2e}', '0x35, 0x34, 0x65, 0x9b, 0x1c, 0x2e'],
            ['#define password {0x35, 0x34, 0x65, 0x9b, 0x1c, 0x2e \\', '0x35, 0x34, 0x65, 0x9b, 0x1c, 0x2e \\'],
            ['#define password ";,}d4s@\\on"', ";,}d4s@\\on"],
            ['%define password "CEKPET"', "CEKPET"],
            ["set password CEKPET", "CEKPET"],
            ['password = get_password(option1="CEKPET", option2="KOMETA")', "CEKPET"],
            [
                '{"PWD":[{"kty":"oct","kid":"25b58GCM","k":"Xc_2A"},{"kty":"oct","kid":"09b51KW","k":"KG6wlB-6sIVQ"}]',
                '"kty":"oct","kid":"25b58GCM","k":"Xc_2A"'
            ],
            [
                '{"PWD":[{"ktyX":"oct","kid":"25b58GCM","k":"Xc_2A"},{"kty":"oct","kid":"09b51KW","k":"KG6wlB-6sIVQ"}]',
                'ktyX'  # todo "ktyX":"oct","kid":"25b58GCM","k":"Xc_2A"
            ],
            ["pass = Super::Encryptor('seCreT', 'secRet2');", "seCreT"],
            ['PWD = {"123": "08c8b5b3", 456: "07c6aa05"}', '"123": "08c8b5b3", 456: "07c6aa05"'],
            ['PWD = {"1234": "abcd", 1: "efgh"}', '1234'],
            ["password: { other_secret: 'GehE1mNi5',", "GehE1mNi5"],
            ["byte[] password = new byte[]{0x3, 0x5, 0x8, 0x3, 0x5, 0x8};", "0x3, 0x5, 0x8, 0x3, 0x5, 0x8"],
            ["byte[]password=new byte[]{0x3,0x5,0x8,0x3,0x5,0x8};", "0x3,0x5,0x8,0x3,0x5,0x8"],
            ["char[] password = new char[]{'f',\\x03, 02 ,'1', 0};", "'f',\\x03, 02 ,'1', 0"],
            ["char password[] = {'H', 'e', 'l', 'l', 'o', '\0'};", "'H', 'e', 'l', 'l', 'o', '\0'"],
            ["char password[] = {0x34, 0x53, 0x53, 0x62, 000};", "0x34, 0x53, 0x53, 0x62, 000"],
            ["char[] password = new char[]{'b', 'y', 't', 'e', 's', '\\0'};", "'b', 'y', 't', 'e', 's', '\\0'"],
            ["char[] password = new char[]{023, 010, 041, 033, 043, 000};", "023, 010, 041, 033, 043, 000"],
            ['final String [] password = new String [] { "GehE1mNi5",', 'GehE1mNi5'],
            ["private static readonly byte[] password = new byte[] { 'X','3', '4', '0'   \\", "'X','3', '4', '0'   \\"],
            ["password=${REMOVE_PREFIX#prefix}", "${REMOVE_PREFIX#prefix}"],
            ["password='${REMOVE_PREFIX#prefix}'", "${REMOVE_PREFIX#prefix}"],
            ["password=${cat pass}", "${cat"],
            ['password=$(echo "pass")', "$(echo"],
            ["password='$(( 1 + 2 + 3 + 4 ))'", "$(( 1 + 2 + 3 + 4 ))"],
            ["password=$(( 1 + 2 + 3 + 4 ))", "$(( 1 + 2 + 3 + 4 ))"],
            ["password='$[[ 1 + 2 + 3 + 4 ]]'", "$[[ 1 + 2 + 3 + 4 ]]"],
            ["password=$[[ 1 + 2 + 3 + 4 ]]", ""],  # obsolete
            ["password=$[[_1_+_2_+_3_+_4_]]", "$[[_1_+_2_+_3_+_4_]]"],
            ["password=${array[@]:7:2}", "${array[@]:7:2}"],
            ["password=${1#*=}", "${1#*=}"],
            ["A2 ID:master,PW:dipPr10Gg!", "dipPr10Gg!"],
            ["pass=get->pass(arg1='seCreT', arg2='secRet2'...", "seCreT"],
            ["The test password => skWu850", "skWu850"],
            ["$password = Hash::make('GehE1mNi5');", "GehE1mNi5"],
            ['password = new[] {"GehE1mNi5"}', "GehE1mNi5"],
            ["password, _ = hex.DecodeString('e1efa5ca09a6beac387c04a5cdc1d491')", "e1efa5ca09a6beac387c04a5cdc1d491"],
            ["MY_TEST_PASSWORD='(MY_TEST_PASSWORD)'", "(MY_TEST_PASSWORD)"],
            ["MY_TEST_PASSWORD=$(MY_TEST_PASSWORD)", "$(MY_TEST_PASSWORD)"],
            ["MY_TEST_PASSWORD='$(MY_TEST_PASSWORD)'", "$(MY_TEST_PASSWORD)"],
            # https://www.gnu.org/savannah-checkouts/gnu/bash/manual/bash.html#Shell-Expansions
            ["MY_TEST_PASSWORD=${MY_VAR:?THE VAR IS UNSET}", "${MY_VAR:?THE"],
            ['''ClientPasswords = new[] { new Password( "SECRET".Sha256() ) },''', "SECRET"],
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
            ["""'password': t'{secret}'""", """{secret}"""],  #
            ["""\\'password\\': \\'secret\\'""", """secret"""],  #
            ['''db.setCred("{ \"password\" : \"" + SECRET + "\" }");''', ''' + SECRET + '''],
            ['''\\"password\\": \\"{\\\\"secret\\\\": \\\\"test\\\\"}\\"''', '{\\\\"secret\\\\": \\\\"test\\\\"}'],  #
            ['''"password": "{\\\\"secret\\\\": \\\\"test\\\\"}"''', '{\\\\"secret\\\\": \\\\"test\\\\"}'],  #
            # normal_str = "First line.\nSecond line.\nEnd of message.\n";
            ['''std::string password = R"multiline\\npassword";''', '''multiline\\npassword'''],  #
            ['''const wchar_t* password = L"wchar_t*secret";''', '''wchar_t*secret'''],  #
            ['''const char16_t* password = U"char16_t*secret";''', '''char16_t*secret'''],  #
            ["""char password[] = {'S', 'E', 'C', 'R', 'E', 'T', '\\0'};""", """'S', 'E', 'C', 'R', 'E', 'T', '\\0'"""
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
        line_data = LineData(config,
                             line,
                             0,
                             1,
                             file_path,
                             Util.get_extension(file_path),
                             info="dummy",
                             pattern=KEYWORD_PASSWORD_PATTERN)
        assert line_data.value == value, KEYWORD_PASSWORD_PATTERN.pattern

    @pytest.mark.parametrize("line", [
        "set_unusable_api() should not found",
        "https://fonts.googleapis.com/css2?family=Montserrat:wght@500;700;900&family=Roboto:wght@300;400;500;700;900"
        "&family=Roboto+Mono:wght@300;400;600;900&display=swap",
        "reset api example",
    ])
    def test_keyword_pattern_n(self, config: Config, file_path: pytest.fixture, line: str) -> None:
        pattern = KeywordPattern.get_keyword_pattern("api")
        line_data = LineData(config, line, 0, 1, file_path, "file_type", "info", pattern)
        assert line_data.value is None
