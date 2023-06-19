import random
import re
import statistics
import string
import sys
import time
from typing import List

from regex import regex

TEST_REPEAT = 100
SIZE = 1 << 20


def perf_match_re(text, rule: re.Pattern) -> int:
    result = 0
    for i in text:
        if rule.match(i):
            result += 1
    return result


def perf_match_regex(text, rule: regex.Pattern) -> int:
    result = 0
    for i in text:
        if rule.match(i):
            result += 1
    return result


def perf_search_re(text, rule: re.Pattern) -> int:
    result = 0
    for i in text:
        if rule.search(i):
            result += 1
    return result


def perf_search_regex(text, rule: regex.Pattern) -> int:
    result = 0
    for i in text:
        if rule.search(i):
            result += 1
    return result


def get_random_text(lines_number) -> List[str]:
    text = []
    # alphabet = string.digits + string.ascii_letters + string.punctuation + " \t"
    alphabet = string.digits + "-.,_ \t"
    for i in range(lines_number):
        line = ""
        for x in range(random.randint(1, 1500)):
            line += random.choice(alphabet)
        text.append(line)
    return text


def perf_test(rule_re, rule_regex):
    stat_match_re = []
    stat_match_regex = []
    stat_search_re = []
    stat_search_regex = []
    for n in range(TEST_REPEAT):
        text = get_random_text(10000)

        start_time = time.time()
        result_re = perf_match_re(text, rule_re)
        stat_match_re.append(time.time() - start_time)
        print(f"_match re {time.time() - start_time}", flush=True)

        start_time = time.time()
        result_regex = perf_match_regex(text, rule_regex)
        stat_match_regex.append(time.time() - start_time)
        print(f"_match regex {time.time() - start_time}", flush=True)

        start_time = time.time()
        result_re = perf_search_re(text, rule_re)
        stat_search_re.append(time.time() - start_time)
        print(f"_search re {time.time() - start_time}", flush=True)

        start_time = time.time()
        result_regex = perf_search_regex(text, rule_regex)
        stat_search_regex.append(time.time() - start_time)
        print(f"_search regex {time.time() - start_time}", flush=True)

        assert result_re == result_regex, f"{result_re} <> {result_regex}"

    mean = statistics.mean(stat_match_re)
    print(f"RE _match Average = {mean} Deviation = {statistics.stdev(stat_match_re, mean)}", flush=True)
    mean = statistics.mean(stat_match_regex)
    print(f"REGEX _match Average = {mean} Deviation = {statistics.stdev(stat_match_regex, mean)}", flush=True)
    mean = statistics.mean(stat_search_re)
    print(f"RE _search Average = {mean} Deviation = {statistics.stdev(stat_search_re, mean)}", flush=True)
    mean = statistics.mean(stat_search_regex)
    print(f"REGEX _search Average = {mean} Deviation = {statistics.stdev(stat_search_regex, mean)}", flush=True)


def main() -> int:
    # first test for big text
    big_text = get_random_text(50000)
    templ_rule = r"(^|[^0-9A-Za-z])(?P<value>([0-9A-Za-z\-_]{15}|[A-Z2-7]{16}))"
    rule_re = re.compile(templ_rule)
    rule_regex = regex.compile(templ_rule)

    start_time = time.time()
    perf_test(rule_re, rule_regex)
    print(f"Total time: {time.time() - start_time} SIZE={SIZE}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#  r"(^|[^0-9A-Za-z])(?P<value>[0-9A-Za-z\-_]{15})"
# match
# RE Average = 0.0018892335891723634 Deviation = 0.0001420162677764334
# REGEX Average = 0.004629347324371338 Deviation = 0.0003729679985738683
# search
# RE Average = 0.07180695533752442 Deviation = 0.004711844471508342
# REGEX Average = 0.18683056592941283 Deviation = 0.013616488653569231

# r"(^|[^0-9A-Za-z])(?P<value>([0-9A-Za-z\-_]{15}|[A-Z2-7]{16}))"
# RE _match Average = 0.002278308868408203 Deviation = 0.00014856680238041614
# REGEX _match Average = 0.005020983219146728 Deviation = 0.0002603267867627549
# RE _search Average = 0.09171557188034057 Deviation = 0.003268669311398806
# REGEX _search Average = 0.22659739017486571 Deviation = 0.008601584942025875
