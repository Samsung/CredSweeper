# CredSweeper

<img src="https://raw.githubusercontent.com/Samsung/CredSweeper/main/docs/images/Logo.png" width="500"/>

## Table of Contents

   * [Introduction](#introduction)
   * [How To Use](#how-to-use)
	   * [Main Requirements](#main-requirements)
     * [Installation](#installation)
       * [Via pip](#via-pip)
       * [Via git clone (dev install)](#via-git-clone-dev-install)
     * [Run](#run)
     * [Tests](#tests)
     * [Benchmark](#benchmark)
   * [Overall Architecture](#overall-architecture)
   * [License](#license)
   * [How to Get Involved](#how-to-get-involved)
   * [How to Contact](#how-to-contact)

## Introduction

CredSweeper is a tool to detect credentials in any directories or files. CredSweeper could help users to detect unwanted exposure of credentials  (such as personal information, token, passwords, api keys and etc) in advance. By scanning lines, filtering, and using AI model as option, CredSweeper reports lines with possible credentials, where the line is, and expected type of the credential as a result.

## How To Use
### Main Requirements

- Python3.7 or higher

### Installation
#### Via pip

Without Ml validation feature
```bash
pip install credsweeper
```

With Ml validation feature
```bash
pip install credsweeper[ml]
```

#### Via git clone (dev install)

``` bash
git clone https://github.com/Samsung/CredSweeper.git
cd CredSweeper
# Annotate "numpy", "scikit-learn", and "tensorflow" if you don't want to use the ML validation feature.
pip install -qr requirements.txt 
```

### Run

Get all argument list:
``` bash
python -m credsweeper --help
```
``` java
usage: python -m credsweeper [-h] (--path PATH [PATH ...] | --diff_path PATH [PATH ...]) [--rules [PATH]] [--ml_validation] [-b POSITIVE_INT] [--api_validation] [-j POSITIVE_INT] [--skip_ignored] [--save-json [PATH]] [-l LOG_LEVEL]

optional arguments:
  -h, --help            show this help message and exit
  --path PATH [PATH ...]
                        file or directory to scan
  --diff_path PATH [PATH ...]
                        git diff file to scan
  --rules [PATH]        path of rule config file (default: credsweeper/rules/config.yaml)
  --ml_validation       ml validation option on
  -b POSITIVE_INT, --ml_batch_size POSITIVE_INT
                        batch size for model inference (default: 16)
  --api_validation      api validation option on
  -j POSITIVE_INT, --jobs POSITIVE_INT
                        number of parallel processes to use (default: number of CPU cores * 2)
  --skip_ignored        parse .gitignore files and skip credentials from ignored objects
  --save-json [PATH]    save result to json file (default: output.json)
  -l LOG_LEVEL, --log LOG_LEVEL
                        provide logging level. Example --log debug, (default: 'warning'), 
                          detailed log config: credsweeper/secret/log.yaml 
```

Get output as JSON file:
``` bash
python -m credsweeper --ml_validation --path tests/samples/password --save-json output.json
```
``` rb
rule: Password / severity: medium / line_data_list: [line : 'password = "cackle!"' / line_num : 1 / path : tests/samples/password / entropy_validation: False] / api_validation: NOT_AVAILABLE / ml_validation: VALIDATED_KEY
```
To check JSON file run:
```bash
cat output.json
```
``` json
[
    {
        "rule": "Password",
        "severity": "medium",
        "line_data_list": [
            {
                "line": "password = \"cackle!\"",
                "line_num": 1,
                "path": "tests/samples/password",
                "entropy_validation": false
            }
        ],
        "api_validation": "NOT_AVAILABLE",
        "ml_validation": "VALIDATED_KEY"
    }
]
```

Get CLI output only:
``` bash
python -m credsweeper --ml_validation --path tests/samples/password
```
``` rb
rule: Password / severity: medium / line_data_list: [line : 'password = "cackle!"' / line_num : 1 / path : tests/samples/password / entropy_validation: False] / api_validation: NOT_AVAILABLE / ml_validation: VALIDATED_KEY
```

### Tests

To run all tests:
``` bash
python -m pytest --cov=credsweeper --cov-report=term-missing -s tests/
```

To run only tests independent from external api:
``` bash
python -m pytest -m "not api_validation" --cov=credsweeper --cov-report=term-missing -s tests/
```

### Benchmark

We have a dataset for testing credential scanners that called [CredData](https://github.com/Samsung/CredData). If you want to test CredSweeper with this dataset please check [here](https://github.com/Samsung/CredData/blob/main/README.md#benchmark).

## Overall Architecture

To check overall architecture of CredSweeper please check [here](docs/overall_architecture.md).


## License

The CredSweeper is an Open Source project released under the terms of [MIT License V2](https://opensource.org/licenses/mit-license.php).

## How to Get Involved

In addition to developing under an Open Source license, A use an Open Source Development approach, welcoming everyone to participate, contribute, and engage with each other through the project.

### Project Roles

A recognizes the following formal roles: Contributor and Maintainer. Informally, the community may organize itself and give rights and responsibilities to the necessary people to achieve its goals.

#### Contributor

A Contributor is anyone who wishes to contribute to the project, at any level. Contributors are granted the following rights, to:
- Contribute code, documentation, translations, artwork, and etc.
- Report defects (bugs) and suggestions for enhancement.
- Participate in the process of reviewing contributions by others.

If you want to participate in the project development, check out the [how to contribute guideline](./docs/howto/how-to-contribute.md) in advance.

Contributors who show dedication and skill are rewarded with additional rights and responsibilities. Their opinions weigh more when decisions are made, in a fully meritocratic fashion.

#### Maintainer

A Maintainer is a Contributor who is also responsible for knowing, directing and anticipating the needs of a given a Module. As such, Maintainers have the right to set the overall organization of the source code in the Module, and the right to participate in the decision-making. Maintainers are required to review the contributor’s requests and decide whether to accept or not.

Name | E-Mail
-- | --
[Jaeku Yun](https://github.com/silentearth) | jk0113.yun@samsung.com
[Shinhyung Choi](https://github.com/csh519) | sh519.choi@samsung.com
[Yujeong Lee](https://github.com/yuzzyuzz) | yujeongg.lee@samsung.com
[Oleksandra Sokol](https://github.com/meanrin) | o.sokol@samsung.com
[Dmytro Kuzmenko](https://github.com/Dmitriy-NK) | d.kuzmenko@samsung.com
[Arkadiy Melkonyan](https://github.com/ARKAD97) | a.melkonyan@samsung.com

## How to Contact

Please post questions, issues, or suggestions into Issues, This is the best way to communicate with the developer.
