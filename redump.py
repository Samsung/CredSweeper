#!/usr/bin/env python3
import json
import sys


def redump(j: list) -> str:
    lines = []
    for i in j:
        lines.append(json.dumps(i, sort_keys=True))
    lines.sort()

    first_item = True
    text = "["
    for i in lines:
        if first_item:
            first_item = False
        else:
            text += '\n,'
        text += i
    text += '\n]'
    return text


def main(argv):
    with open(argv[1], "r") as f:
        ara = json.load(f)
    if isinstance(ara, list):
        print(redump(ara))


if "__main__" == __name__:
    sys.exit(main(sys.argv))
