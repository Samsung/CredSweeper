import unittest

from credsweeper.progress import Progress


class ProgressTest(unittest.TestCase):

    def test_callback_n(self):
        self.assertIsNone(Progress().progress_bar)

    def test_callback_p(self):
        p = Progress()
        p.callback("test", 1, 2)
        self.assertIsNotNone(p.progress_bar)
        p.callback("test", 2, 2)
        self.assertIsNone(p.progress_bar)
