from unittest import TestCase

from credsweeper.utils import Util
from tests import CREDSWEEPER_DIR


class ConfigTest(TestCase):

    def test_extension_check_p(self):
        file_name = CREDSWEEPER_DIR / "secret" / "config.json"
        config_dict = Util.json_load(str(file_name))
        self.assertIsNotNone(config_dict)
        self.assertTrue(isinstance(config_dict, dict))
        self.assertIn("exclude", config_dict.keys())
        self.assertTrue(isinstance(config_dict["exclude"], dict))
        self.assertIn("containers", config_dict["exclude"].keys())
        self.assertTrue(isinstance(config_dict["exclude"]["containers"], list))
        self.assertIn("extension", config_dict["exclude"].keys())
        self.assertTrue(isinstance(config_dict["exclude"]["extension"], list))
        container_set = set(config_dict["exclude"]["containers"])
        extension_set = set(config_dict["exclude"]["extension"])
        # the sets MUST have no intersection
        self.assertFalse(container_set.intersection(extension_set))
