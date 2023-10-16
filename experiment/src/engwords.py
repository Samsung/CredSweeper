import binascii
import sys


def main() -> int:
    with open("words_alpha.txt", "r") as f:
        lines = f.readlines()
    crc32set = dict()
    for i in lines:
        x = binascii.crc32(i.encode("ascii"))
        if x in crc32set:
            print(x, i, crc32set[x])
        else:
            crc32set[x] = i
    print(len(crc32set))
    return 0


if """__main__""" == __name__:
    sys.exit(main())
