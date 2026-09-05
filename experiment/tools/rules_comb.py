import yaml

from credsweeper.scanner.scanner import RULES_PATH


def main():
    with open(RULES_PATH, 'r', encoding='utf-8') as fi:
        rules = yaml.safe_load(fi)

    with open(RULES_PATH, 'w', encoding='utf-8') as fo:
        for n, r in enumerate(rules):
            if n:
                fo.write("\n")
            fo.write(f"- name: {r['name']}\n")
            fo.write(f"  severity: {r['severity']}\n")
            fo.write(f"  confidence: {r['confidence']}\n")
            fo.write(f"  type: {r['type']}\n")
            fo.write(f"  values:\n")
            for v in r['values']:
                fo.write(f"    - {v}\n")
            if 'filter_type' in r:
                if isinstance(r['filter_type'], str):
                    fo.write(f"  filter_type: {r['filter_type']}\n")
                elif isinstance(r['filter_type'], list):
                    if r['filter_type']:
                        fo.write(f"  filter_type:\n")
                        for ft in r['filter_type']:
                            fo.write(f"    - {ft}\n")
                    else:
                        fo.write(f"  filter_type: [ ]\n")
                else:
                    raise TypeError(f"{r} {type(r['filter_type'])}")
            if 'min_line_len' in r:
                fo.write(f"  min_line_len: {r['min_line_len']}\n")
            if 'required_substrings' in r:
                fo.write(f"  required_substrings:\n")
                for rs in r['required_substrings']:
                    if rs in ('.', '|', '-', "NO", "3MVG", "00D"):
                        fo.write(f'    - "{rs}"\n')
                    else:
                        fo.write(f"    - {rs}\n")
            if 'required_regex' in r:
                fo.write(f"""  required_regex: "{r['required_regex']}"\n""")
            if 'use_ml' in r:
                fo.write(f"  use_ml: {str(r['use_ml']).lower()}\n")
            fo.write(f"  target:\n")
            for t in r['target']:
                fo.write(f"    - {t}\n")


if __name__ == '__main__':
    main()
