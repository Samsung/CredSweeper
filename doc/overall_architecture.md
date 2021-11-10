# Overall Architecture

* [Pre-processing](#pre-processing)
  * [Scan](#scan)
    * [Rule](#rule)
    * [Filter](#filter)
  * [ML validation](#ml-validation)

CredSweeper is largely composed of 3 parts as follows. ([Pre-processing](#pre-processing), [Scan](#scan), [ML validation](#ml-validation))

<img src="images/Architecture.png" width="1220"/>

## Pre-processing

When paths to scan are entered, get the files in that paths and the files are excluded based on the list created by [config.json](../credsweeper/secret/config.json).

**config.json**

``` json
    ...
    "exclude": {
        "pattern": [
            ...
        ],
        "extension": [
            ".7z",
            ".JPG",
            ...

        ],
        "path": [
            "/.git/",
            "/.idea/",
            ...
        ]
    }
    ...
```

## Scan

Basically, scanning is performed for each file path with a pool of cpu core * 2, and it is performed based on the [Rule](#rule)s. Scanning method differs from scan type of the [Rule](#rule), which is assigned when the [Rule](#rule) is generated. There are 3 scan types: [SinglePattern](credsweeper/scanner/scan_type/single_pattern.py), [MultiPattern](credsweeper/scanner/scan_type/multi_pattern.py), and [PEMKeyPattern](credsweeper/scanner/scan_type/pem_key_pattern.py). Below is the description of the each scan type and its scanning method.

- [SinglePattern](credsweeper/scanner/scan_type/single_pattern.py)
  - When : The [Rule](#rule) has only 1 pattern.
  - How : Check if a single line Rule pattern present in the line.
- [MultiPattern](credsweeper/scanner/scan_type/multi_pattern.py)
  - When : The [Rule](#rule) has 2 patterns.
  - How : Check if a line is a part of a multi-line credential and the remaining part exists within 10 lines below.
- [PEMKeyPattern](credsweeper/scanner/scan_type/pem_key_pattern.py)
  - When : The [Rule](#rule) type is `pem_key`.
  - How : Check if a line’s entropy is high enough and the line have no substring with 5 same consecutive characters. (like 'AAAAA')

### Rule

Each [Rule](#rule) is dedicated to detect a specific type of credential, imported from [config.yaml](credsweeper/rules/config.yaml) at the runtime.

**config.yaml** 

```yaml
  ...
- name: API
  severity: medium
  type: keyword
  values:
  - api
  filter_type: GeneralKeyword
  use_ml: true
  validations: []
- name: AWS Client ID
  ...
```

**Rule Attributes** 

- severity
  - [Severity](credsweeper/common/constants.py)
    
    ``` python
    ...
    class Severity(Enum):
        CRITICAL = "critical"
        HIGH = "high"
        MEDIUM = "medium"
        LOW = "low"
    ...
    ```
- type
  - [RuleType](credsweeper/common/constants.py)
    
    ``` python
    ...
    class RuleType(Enum):
        KEYWORD = "keyword"
        PATTERN = "pattern"
        PEM_KEY = "pem_key"
    ...
    ```
- values
  - keyword : The keywords you want to detect. If you want to detect multiple keywords, you can write them as follows : `password|passwd|pwd`.
  - pattern : The patterns you want to detect. For more accurate detection, it is recommended to specify `?P<value>` in the patterns : `(?P<value>AIza[0-9A-Za-z\-_]{35})`.
- filter_type
  - The type of the [Filter](#filter) group you want to apply. [Filter](#filter) groups implemented are as follows: [GeneralKeyword](credsweeper/filters/group/general_keyword.py), [GeneralPattern](credsweeper/filters/group/general_pattern.py), [PasswordKeyword](credsweeper/filters/group/password_keyword.py), and [UrlCredentials](credsweeper/filters/group/url_credentials_group.py).
- use_ml
  - The attribute to set whether to perform ML validation. If true, ML validation will be performed.
- validations
  - The type of the validation you want to apply. Validations implemented are as follows: [GithubTokenValidation](credsweeper/validations/github_token_validation.py), [GoogleApiKeyValidation](credsweeper/validations/google_api_key_validation.py), [GoogleMultiValidation](credsweeper/validations/google_multi_validation.py), [MailchimpKeyValidation](credsweeper/validations/mailchimp_key_validation.py), [StackTokenValidation](credsweeper/validations/stack_token_validation.py), [SquareAccessTokenValidation](credsweeper/validations/square_access_token_validation.py), [SquareClientIdValidation](credsweeper/validations/square_client_id_validation.py), and [StripeApiKeyValidation](credsweeper/validations/stripe_api_key_validation.py).

### Filter

Check the detected candidates from the formal step. If a candidate is caught by the [Filter](#filter), it is removed from the candidates set.
There are 21 filters and 4 filter groups. [Filter](#filter) group is a set of [Filter](#filter)s, which is designed to use many [Filter](#filter)s effectively at the same time.

## ML validation

CredSweeper provides pre-trained ML models to filter false credential lines.
Users can use [ML validation](#ml-validation) by explicitly setting the command option.

``` bash
$ python -m credsweeper --ml_validation --path $TARGET_REPO
```
ML model classifies whether the target line is a credential or not.
The model is constructed by the combination of Linear Regression model and biLSTM model using character set, trained by sample credential lines.
Below figure is the model architecture.

<img src="images/Model_with_features.png" width="650"/>

Linear Regression model takes feature vector with a value of 1 if the corresponding rule is met, and 0 if not as an input.
For the complete description of the rules applied, you can read [this publication](https://ieeexplore.ieee.org/abstract/document/9027350).

```
@INPROCEEDINGS{9027350,
    author={Saha, Aakanksha and Denning, Tamara and Srikumar, Vivek and Kasera, Sneha Kumar},  
    booktitle={2020 International Conference on COMmunication Systems   NETworkS (COMSNETS)},   
    title={Secrets in Source Code: Reducing False Positives using Machine Learning},   
    year={2020}, 
    pages={168-175},  
    doi={10.1109/COMSNETS48256.2020.9027350}
}
```
