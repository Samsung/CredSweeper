import random
import string

import numpy as np
import scipy

from credsweeper.utils import Util

if __name__ == "__main__":
    # print(scipy.stats.skew([4,4,3,6,4,4,5,3]))

    for n in range(16, 100):
        random_bytes = random.randbytes(n)
        assert Util.small_data_random_test(random_bytes), random_bytes

    assert not Util.small_data_random_test(b'\xFF012345678901234\0')

    for n in range(12, 100):
        random_string = ''.join(random.choice(string.printable) for _ in range(n))
        assert not Util.small_data_random_test(random_string.encode('ascii')), random_string

    # chess test
    assert not Util.small_data_random_test(
        b'\xA5\x5A\xA5\x5A\xA5\x5A\xA5\x5A\xA5\x5A\xA5\x5A\xA5\x5A\xA5\x5A\xA5\x5A\xA5\x5A')
    assert not Util.small_data_random_test(
        b'\xFF\x00\xFF\x00\xFF\x00\xFF\x00\xFF\x00\xFF\x00\xFF\x00\xFF\x00\xFF\x00\xFF\x00')