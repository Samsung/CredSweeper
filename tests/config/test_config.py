from unittest import TestCase

from credsweeper.app import APP_PATH
from credsweeper.utils.util import Util


class ConfigTest(TestCase):

    def test_extension_check_p(self):
        file_name = APP_PATH / "secret" / "config.json"
        self.config = Util.json_load(str(file_name))
        self.assertIsNotNone(self.config)
        self.assertTrue(isinstance(self.config, dict))
        self.assertIn("exclude", self.config.keys())
        self.assertTrue(isinstance(self.config["exclude"], dict))
        self.assertIn("containers", self.config["exclude"].keys())
        self.assertTrue(isinstance(self.config["exclude"]["containers"], list))
        self.assertIn("extension", self.config["exclude"].keys())
        self.assertTrue(isinstance(self.config["exclude"]["extension"], list))
        container_set = set(self.config["exclude"]["containers"])
        extension_set = set(self.config["exclude"]["extension"])
        # the sets MUST have no intersection
        self.assertFalse(container_set.intersection(extension_set))
        # all extensions MUST be in lower
        self.assertTrue(all(i.islower() for i in container_set))
        self.assertTrue(all(i.islower() for i in extension_set))
