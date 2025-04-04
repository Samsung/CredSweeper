import unittest

from credsweeper.utils.hop_stat import HopStat


class TestHopStat(unittest.TestCase):

    def test_hop_stat_n(self):
        HopStat()
        with self.assertRaises(ValueError):
            HopStat().stat('34')
        with self.assertRaises(ValueError):
            HopStat().stat('1')
        with self.assertRaises(ValueError):
            HopStat().stat('1')

    def test_hop_stat_p(self):
        self.assertTupleEqual((1, 0), HopStat().stat("qwerty"))
