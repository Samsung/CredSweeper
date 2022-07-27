Overall Architecture
====================

CredSweeper is largely composed of 3 parts as follows. (Pre-processing_, Scan_, `ML validation`_)

.. image:: https://raw.githubusercontent.com/Samsung/CredSweeper/main/docs/images/Architecture.png

Pre-processing
--------------

When paths to scan are entered, get the files in that paths and the files are excluded based on the list created by `config.json <apps_config.html>`_.

**config.json**

- exclude
   - pattern: Regex patterns to exclude scan.
   - extension: Extensions to exclude scan.
   - path: Paths to exclude scan.
- source_ext: List of extensions for scanning categorized as source files.
- source_quote_ext: List of extensions for scanning categorized as source files that using quote.
- find_by_ext_list: List of extensions to detect only extensions.
- check_for_literals: Bool value for whether to check line has string literal declaration or not.
- line_data_output: List of attributes of `line_data <credentials.html#module-credsweeper.credentials.line_data>`_ for output.
- candidate_output: List of attributes of `candidate <credentials.html#module-credsweeper.credentials.candidate>`_ for output.

.. code-block:: text

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

Scan
----


Basically, scanning is performed for each file path, and it is performed based on the Rule_. Scanning method differs from scan type of the Rule_, which is assigned when the Rule_ is generated. There are 3 scan types: `SinglePattern <scanner.scan_type.html#module-credsweeper.scanner.scan_type.single_pattern>`_, `MultiPattern <scanner.scan_type.html#module-credsweeper.scanner.scan_type.multi_pattern>`_, and `PEMKeyPattern <scanner.scan_type.html#module-credsweeper.scanner.scan_type.pem_key_pattern>`_. Below is the description of the each scan type and its scanning method.

- `SinglePattern <scanner.scan_type.html#module-credsweeper.scanner.scan_type.single_pattern>`_
  - When : The Rule_ has only 1 pattern.
  - How : Check if a single line Rule pattern present in the line.
- `MultiPattern <scanner.scan_type.html#module-credsweeper.scanner.scan_type.multi_pattern>`_
  - When : The Rule_ has 2 patterns.
  - How : Check if a line is a part of a multi-line credential and the remaining part exists within 10 lines below.
- `PEMKeyPattern <scanner.scan_type.html#module-credsweeper.scanner.scan_type.pem_key_pattern>`_
  - When : The Rule_ type is `pem_key`.
  - How : Check if a line’s entropy is high enough and the line have no substring with 5 same consecutive characters. (like 'AAAAA')

Rule
----

Each Rule_ is dedicated to detect a specific type of credential, imported from `config.yaml <rules_config.html>`_ at the runtime.

**config.yaml**

.. code-block:: yaml

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

**Rule Attributes** 

- severity
  - `Severity <common.html#credsweeper.common.constants.Severity>`_

.. code-block:: python

    ...
    class Severity(Enum):
        CRITICAL = "critical"
        HIGH = "high"
        MEDIUM = "medium"
        LOW = "low"
    ...

- type
  - `RuleType <common.html#credsweeper.common.constants.RuleType>`_
    
.. code-block:: python

    ...
    class RuleType(Enum):
        KEYWORD = "keyword"
        PATTERN = "pattern"
        PEM_KEY = "pem_key"
    ...

- values
  - keyword : The keywords you want to detect. If you want to detect multiple keywords, you can write them as follows : `password|passwd|pwd`.
  - pattern : The patterns you want to detect. For more accurate detection, it is recommended to specify `?P<value>` in the patterns : `(?P<value>AIza[0-9A-Za-z\-_]{35})`.
- filter_type
  - The type of the Filter_ group you want to apply. Filter_ groups implemented are as follows: `GeneralKeyword <filters.group.html#module-credsweeper.filters.group.general_keyword>`_, `GeneralPattern <filters.group.html#module-credsweeper.filters.group.general_pattern>`_, `PasswordKeyword <filters.group.html#module-credsweeper.filters.group.password_keyword>`_, and `UrlCredentials <filters.group.html#module-credsweeper.filters.group.url_credentials_group>`_.
- use_ml
  - The attribute to set whether to perform ML validation. If true, ML validation will be performed.
- validations
  - The type of the validation you want to apply. Validations implemented are as follows: `GithubTokenValidation <validations.html#module-credsweeper.validations.github_token_validation>`_, `GoogleApiKeyValidation <validations.html#module-credsweeper.validations.google_api_key_validation>`_, `GoogleMultiValidation <validations.html#module-credsweeper.validations.google_multi_validation>`_, `MailchimpKeyValidation <validations.html#module-credsweeper.validations.mailchimp_key_validation>`_, `SlackTokenValidation <validations.html#module-credsweeper.validations.slack_token_validation>`_, `SquareAccessTokenValidation <validations.html#module-credsweeper.validations.square_access_token_validation>`_, `SquareClientIdValidation <validations.html#module-credsweeper.validations.square_client_id_validation>`_, and `StripeApiKeyValidation <validations.html#module-credsweeper.validations.stripe_api_key_validation>`_.

Filter
------

Check the detected candidates from the formal step. If a candidate is caught by the Filter_, it is removed from the candidates set.
There are 21 filters and 4 filter groups. Filter_ group is a set of Filter_s, which is designed to use many Filter_s effectively at the same time.

ML validation
-------------

CredSweeper provides pre-trained ML models to filter false credential lines.
Users can use `ML validation`_ by explicitly setting the command option.

.. code-block:: bash

    python -m credsweeper --path $TARGET_REPO

ML model classifies whether the target line is a credential or not.
The model is constructed by the combination of Linear Regression model and biLSTM model using character set, trained by sample credential lines.
Below figure is the model architecture.

.. image:: https://raw.githubusercontent.com/Samsung/CredSweeper/main/docs/images/Model_with_features.png

Linear Regression model takes feature vector with a value of 1 if the corresponding rule is met, and 0 if not as an input.
For the complete description of the rules applied, you can read `this publication <https://ieeexplore.ieee.org/abstract/document/9027350>`_.

.. code-block::

    @INPROCEEDINGS{9027350,
        author={Saha, Aakanksha and Denning, Tamara and Srikumar, Vivek and Kasera, Sneha Kumar},  
        booktitle={2020 International Conference on COMmunication Systems   NETworkS (COMSNETS)},   
        title={Secrets in Source Code: Reducing False Positives using Machine Learning},   
        year={2020}, 
        pages={168-175},  
        doi={10.1109/COMSNETS48256.2020.9027350}
    }
