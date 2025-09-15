import unittest

from credsweeper.app import APP_PATH
from credsweeper.common.constants import MAX_LINE_LENGTH, Severity
from credsweeper.config.config import Config
from credsweeper.deep_scanner.deep_scanner import DeepScanner
from credsweeper.file_handler.struct_content_provider import StructContentProvider
from credsweeper.scanner.scanner import Scanner
from credsweeper.utils.util import Util


class TestStructScanner(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        # default config
        config = Util.json_load(APP_PATH / "secret" / "config.json")
        config["pedantic"] = False
        config["depth"] = 0
        config["doc"] = False
        config["use_filters"] = True
        config["find_by_ext"] = False
        config["size_limit"] = None
        config["severity"] = Severity.LOW
        self.config = Config(config)
        self.scanner = DeepScanner(config=self.config, scanner=Scanner(self.config, None))

    def test_scan_n(self):
        provider = StructContentProvider(None)
        self.assertListEqual([], self.scanner.structure_scan(provider, 3, MAX_LINE_LENGTH))

    def test_scan_p(self):
        sample = {
            'API': '\t\t\t   !!!   \r\n',  # strip does small value
            'aUtH': b'\t\t\t   !!!   \r\n',  # bytes are not stripped,
            'dummy': None,
            'self': self,
            'Certificate': 3.14,
            'cReDeNtIaL': 42,
            'PASSWORD': 'Dt1Js8m#1s',
            'Nonce': b'9jY*g76f65D4d5rdy',
            'Key': 'MII5cCI6NiIsInRIkpXV',
            'salt': b"\t'\xDE\xAD\xBE\xEF,1\012\0",
            'key': 'Token',
            'value': '\t-dead-beef-c0de-\n',
        }
        provider = StructContentProvider(sample)
        self.assertListEqual(
            [('Auth', 'aUtH', '\\t\\t\\t   !!!   \\r\\n', "aUtH = b'\\t\\t\\t   !!!   \\r\\n'"),
             ('Key', 'Key', 'MII5cCI6NiIsInRIkpXV', "Key = 'MII5cCI6NiIsInRIkpXV'"),
             ('Nonce', 'Nonce', "9jY*g76f65D4d5rdy", "Nonce = b'9jY*g76f65D4d5rdy'"),
             ('Password', 'PASSWORD', 'Dt1Js8m#1s', "PASSWORD = 'Dt1Js8m#1s'"),
             ('Salt', 'salt', "\\t\'\\xde\\xad\\xbe\\xef,1\\n\\x00", 'salt = b"\\t\'\\xde\\xad\\xbe\\xef,1\\n\\x00"'),
             ('Token', 'Token', '-dead-beef-c0de-', "Token = '-dead-beef-c0de-'")],
            sorted([(x.rule_name, x.line_data_list[0].variable, x.line_data_list[0].value, x.line_data_list[0].line)
                    for x in self.scanner.structure_scan(provider, 3, MAX_LINE_LENGTH)]))
