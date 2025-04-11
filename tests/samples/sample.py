#!/bin/env python


API = \
    "http://127.0.0.1/v0?9e107d9d372bb6826bd81d3542a419d6"

AUTH = \
    "Basic Hbr73gu7gdsr=="

CERTIFICATE = """
MIICXQIBAAKBgQDwcEN7vZygGg6DvPpsw17hRD6S5N8+huaqs1JGXQfPhbvLTUs/
"""

CREDENTIAL=\
'107d9d372bb6826bd81d3542a419d6'

KEY = \
    bytes([223, 66, 216, 52, 221, 30, 216, 36, 216, 55, 216, 1, 216, 82, 223, 98])

NONCE= \
    bytearray([0xDF, 0x42, 0xD8, 0x34, 0xDD, 0x1E, 0xD8, 0x24, 0xD8, 0x37, 0xD8, 0x01, 0xD8, 0x52, 0xDF, 0x62])

PASSWORD = \
        "WeR15tr0n6"

SALT = \
    b"\xDF42\xD834\xDD1E\xD824\xD837\xD801\xD852\xDF62"

SECRET = \
    """\uDF42\uD834\uDD1E\uD824\uD837\uD801\uD852\uDF62"""

TOKENs = [
    """\tTr1ple_qu0tat10n'-m1s5ed\r\n""",  #
    "\ts1mpleD0ubleQu0tedStr1ng\r\n",  #
]  #



if __name__ == "__main__":
    print(API)



