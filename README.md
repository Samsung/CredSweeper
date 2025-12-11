# CredSweeper

[![GitHub release (latestSemVer)](https://img.shields.io/github/v/release/Samsung/CredSweeper)](https://github.com/Samsung/CredSweeper/releases)
[![Documentation Status](https://readthedocs.org/projects/credsweeper/badge/?version=latest)](https://credsweeper.readthedocs.io/en/latest/?badge=latest)
[![License](https://img.shields.io/badge/licence-MIT-green.svg?style=flat)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/credsweeper)](https://pypi.org/project/credsweeper/)
[![Python](https://img.shields.io/pypi/pyversions/credsweeper.svg)](https://badge.fury.io/py/credsweeper)
[![Test](https://github.com/Samsung/CredSweeper/actions/workflows/test.yml/badge.svg)](https://github.com/Samsung/CredSweeper/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/Samsung/CredSweeper/branch/main/graph/badge.svg)](https://codecov.io/gh/Samsung/CredSweeper)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/6055/badge)](https://bestpractices.coreinfrastructure.org/projects/6055)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Samsung/CredSweeper/badge)](https://api.securityscorecards.dev/projects/github.com/Samsung/CredSweeper)

<img src="https://raw.githubusercontent.com/Samsung/CredSweeper/main/docs/images/Logo.png" width="500"/>

- [CredSweeper](#credsweeper)
  - [Introduction](#introduction)
  - [How To Use](#how-to-use)
    - [Main Requirements](#main-requirements)
    - [Installation](#installation)
    - [Run](#run)
    - [Config](#config)
  - [Develop](#develop)
    - [Tests](#tests)
    - [Benchmark](#benchmark)
  - [Overall Architecture](#overall-architecture)
  - [Retrain Model](#retrain-model)
  - [License](#license)
  - [How to Get Involved](#how-to-get-involved)
    - [Project Roles](#project-roles)
      - [Contributor](#contributor)
      - [Maintainer](#maintainer)
  - [How to Contact](#how-to-contact)

## Introduction

CredSweeper is a tool to detect credentials in any directories or files.
CredSweeper could help users to detect unwanted exposure of credentials
(such as tokens, passwords, api keys etc.) in advance.
By scanning lines, filtering, and using AI model as option,
CredSweeper reports lines with possible credentials, where the line is,
and expected type of the credential as a result.

Full documentation can be found here: <https://credsweeper.readthedocs.io/>

## How To Use

### Main Requirements

- Python 3.10, 3.11, 3.12

### Installation

Details [here](https://credsweeper.readthedocs.io/en/latest/install.html).

```bash
pip install credsweeper
```

### Run

[How to use](https://credsweeper.readthedocs.io/en/latest/guide.html).

Get all argument list:

```bash
python -m credsweeper --help
```

Run CredSweeper:

```bash
python -m credsweeper --path tests/samples/password.gradle --save-json output.json
```

To check JSON file run:

```bash
cat output.json
```

```json
[
    {
        "api_validation": "NOT_AVAILABLE",
        "ml_validation": "VALIDATED_KEY",
        "ml_probability": 0.99755,
        "rule": "Password",
        "severity": "medium",
        "confidence": "moderate",
        "line_data_list": [
            {
                "line": "password = \"cackle!\"",
                "line_num": 1,
                "path": "tests/samples/password.gradle",
                "info": "",
                "value": "cackle!",
                "value_start": 12,
                "value_end": 19,
                "variable": "password",
                "entropy": 2.12059
            }
        ]
    }
]
```

### Config

[credsweeper/secret/config.json](credsweeper/secret/config.json) - Configuration file for pre-processing of CredSweeper. For more details please check [here](https://credsweeper.readthedocs.io/en/latest/overall_architecture.html#pre-processing).

You can set the `pattern`, `extension` and `path` you want to exclude from scanning as below.

```json
{
    "exclude": {
        "pattern": [
            "AKIA[0-9A-Z]{9}EXAMPLE",
            ...
        ],
        "extension": [
            "gif",
            "jpg",
            ...
        ],
        "path": [
            "/.git/",
            "/openssl/",
            ...
        ]
    },
    ...
}
```

And you can also set `source_ext`, `source_quote_ext`, `find_by_ext_list`, `check_for_literals`, `line_data_output`, and `candidate_output` as below.

- `source_ext`: List of extensions for scanning categorized as source files.
- `source_quote_ext`: List of extensions for scanning categorized as source files that using quote.
- `find_by_ext_list`: List of extensions to detect only extensions.
- `check_for_literals`: Bool value for whether to check line has string literal declaration or not.
- `line_data_output`: List of attributes of [line_data](credsweeper/credentials/line_data.py) for output.
- `candidate_output`: List of attributes of [candidate](credsweeper/credentials/candidate.py) for output.

```json
{
    ...
    "source_ext": [
        ".py",
        ".cpp",
        ...
    ],
    "source_quote_ext": [
        ".py",
        ".cpp",
        ...
    ],
    "find_by_ext_list": [
        ".pem",
        ".cer",
        ...
    ],
    "check_for_literals": true,
    "line_data_output": [
        "line",
        "line_num",
        ...
    ],
    "candidate_output": [
        "rule",
        "severity",
        ...
    ]
}
```

[credsweeper/rules/config.yaml](credsweeper/rules/config.yaml) - Configuration file for setting Rule. For more details please check [here](https://credsweeper.readthedocs.io/en/latest/overall_architecture.html#rule).

```yaml
...
- name: API
severity: medium
confidence: moderate
type: keyword
values:
- api
filter_type: GeneralKeyword
use_ml: true
validations: []
- name: AWS Client ID
...
```

## Develop

### Tests

To run all tests:

```bash
python -m pytest --cov=credsweeper --cov-report=term-missing -s tests/
```

To run only tests independent of external api:

```bash
python -m pytest -m "not api_validation_test" tests/
```

To obtain manageable (without subprocesses) coverage:

```bash
python -m pytest --cov=credsweeper --cov-report=html tests/ --ignore=tests/test_app.py
```

### Benchmark

We have a dataset for testing credential scanners that called [CredData](https://github.com/Samsung/CredData). If you want to test CredSweeper with this dataset please check [here](https://github.com/Samsung/CredData/blob/main/README.md#benchmark).

## Overall Architecture

To check overall architecture of CredSweeper please check [here](https://credsweeper.readthedocs.io/en/latest/overall_architecture.html).

## Retrain Model

If you want to check how model was trained or retrain it on your own data, please refer to the [experiment](experiment/README.md) folder

## License

The CredSweeper is an Open Source project released under the terms of [MIT License V2](https://opensource.org/licenses/mit-license.php).

## How to Get Involved

In addition to developing under an Open Source license, A use an Open Source Development approach, welcoming everyone to participate, contribute, and engage with each other through the project.

### Project Roles

A recognizes the following formal roles: Contributor and Maintainer. Informally, the community may organize itself and give rights and responsibilities to the necessary people to achieve its goals.

#### Contributor

A Contributor is anyone who wishes to contribute to the project, at any level. Contributors are granted the following rights to:

- Contribute code, documentation, translations, artwork, and etc.
- Report defects (bugs) and suggestions for enhancement.
- Participate in the process of reviewing contributions by others.

If you want to participate in the project development, check out the [how to contribute guideline](./docs/howto/how-to-contribute.md) in advance.

Contributors who show dedication and skill are rewarded with additional rights and responsibilities. Their opinions weigh more when decisions are made, in a fully meritocratic fashion.

#### Maintainer

A Maintainer is a Contributor who is also responsible for knowing, directing and anticipating the needs of a given a Module. As such, Maintainers have the right to set the overall organization of the source code in the Module, and the right to participate in the decision-making. Maintainers are required to review the contributor’s requests and decide whether to accept or not.

| Name                                           | E-Mail                 |
|------------------------------------------------|------------------------|
| [Jaeku Yun](https://github.com/silentearth)    | jk0113.yun@samsung.com |
| [Shinhyung Choi](https://github.com/csh519)    | sh519.choi@samsung.com |
| [Roman Babenko](https://github.com/babenek)    | r.babenko@samsung.com  |
| [Yuliia Tatarinova](https://github.com/Yullia) | yuliia.t@samsung.com   |

## How to Contact

Please post questions, [issues, or suggestions in issues](https://github.com/Samsung/CredSweeper/issues). This is the best way to communicate with the developers.
