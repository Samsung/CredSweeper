import tabulate

from credsweeper.utils import Util

rule_templates = Util.yaml_load("config.yaml")
keys = set()
for x in rule_templates:
    for k in x.keys():
        keys.add(k)
header = [x for x in keys if x not in ["values", "required_substrings", "required_regex", "validations"]]
rows = []
for x in rule_templates:
    row = []
    for h in header:
        row.append(x.get(h))
    rows.append(row)

print(tabulate.tabulate(rows, header))
