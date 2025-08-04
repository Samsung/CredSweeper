#!/usr/env python3
# -*- coding: utf-8 -*-
"""
The script is useful to test patterns of base64 encoded data with 0,1,2 offsets
"""
import base64
import random
import sys


def gen_token(pad: int, txt: bytes) -> bytes:
    trash = random.randbytes(3) + random.randbytes(pad) + txt + random.randbytes(pad) + random.randbytes(3)
    return base64.b64encode(trash, altchars=b"-_")


def main(argv):
    loops = int(argv[1]) if 1 < len(argv) else 1
    inner_pattern = b"XgroqX"
    while 0 < loops:
        loops -= 1
        token0 = gen_token(0, inner_pattern)
        assert b"WGdyb3FY" in token0, token0
        token1 = gen_token(1, inner_pattern)
        assert b"hncm9xW" in token1, token1
        token2 = gen_token(2, inner_pattern)
        assert b"YZ3JvcV" in token2, token2


if __name__ == """__main__""":
    main(sys.argv)
