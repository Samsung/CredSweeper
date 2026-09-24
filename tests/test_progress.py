import unittest

from credsweeper.progress import Progress


class ProgressTest(unittest.TestCase):

    def test_callback_n(self):
        p = Progress()
        self.assertIsNone(p.progress_bar)
        p.callback("test", 1, 9)
        p.callback("fake", 9, 1)
        self.assertIsNone(p.progress_bar)

    def test_callback_p(self):
        p = Progress()
        p.callback("test", 1, 9)
        self.assertIsNotNone(p.progress_bar)
        p.callback("test", 9, 9)
        self.assertIsNone(p.progress_bar)
