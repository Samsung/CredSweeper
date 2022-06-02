How To Use
==========

Run
---

Get all argument list:

.. code-block:: bash

    python -m credsweeper --help


.. code-block::

    usage: python -m credsweeper [-h] (--path PATH [PATH ...] | --diff_path PATH [PATH ...]) [--rules [PATH]] [--find-by-ext] [--ml_validation] [--ml_threshold FLOAT_OR_STR] [-b POSITIVE_INT] [--api_validation]
                             [-j POSITIVE_INT] [--skip_ignored] [--save-json [PATH]] [-l LOG_LEVEL] [--size_limit SIZE_LIMIT] [--version]

    optional arguments:
    -h, --help            show this help message and exit
    --path PATH [PATH ...]
                            file or directory to scan
    --diff_path PATH [PATH ...]
                            git diff file to scan
    --rules [PATH]        path of rule config file (default: credsweeper/rules/config.yaml)
    --find-by-ext         find files by predefined extension.
    --ml_validation       use credential ml validation option. Machine Learning is used to reduce FP (by far).
    --ml_threshold FLOAT_OR_STR
                            setup threshold for the ml model. The lower the threshold - the more credentials will be reported. Allowed values: float between 0 and 1, or any of ['lowest', 'low', 'medium', 'high',
                            'highest'] (default: medium)
    -b POSITIVE_INT, --ml_batch_size POSITIVE_INT
                            batch size for model inference (default: 16)
    --api_validation      add credential api validation option to credsweeper pipeline. External API is used to reduce FP for some rule types.
    -j POSITIVE_INT, --jobs POSITIVE_INT
                            number of parallel processes to use (default: 1)
    --skip_ignored        parse .gitignore files and skip credentials from ignored objects
    --save-json [PATH]    save result to json file (default: output.json)
    -l LOG_LEVEL, --log LOG_LEVEL
                            provide logging level. Example --log debug, (default: 'warning'),
                            detailed log config: credsweeper/secret/log.yaml
    --size_limit SIZE_LIMIT
                        set size limit of files that for scanning (eg. 1GB / 10MiB / 1000)
    --version, -V         show program's version number and exit

.. note::
    Validation by `ML model classifier  <https://credsweeper.readthedocs.io/en/latest/overall_architecture.html#ml-validation>`_ is used to reduce False Positives (by far), but might increase False negatives and execution time.
    So --ml_validation is recommended, unless you want to minimize FN.

    Typical False Positives: `password = "template_password"`

    API validation is also used to reduce FP, but only for some rule types.

Get output as JSON file:

.. code-block:: bash

    python -m credsweeper --ml_validation --path tests/samples/password --save-json output.json

To check JSON file run:

.. code-block:: bash

    cat output.json


.. code-block:: json

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

Get CLI output only:

.. code-block:: bash

    python -m credsweeper --ml_validation --path tests/samples/password


.. code-block:: ruby

    rule: Password / severity: medium / line_data_list: [line : 'password = "cackle!"' / line_num : 1 / path : tests/samples/password / entropy_validation: False] / api_validation: NOT_AVAILABLE / ml_validation: VALIDATED_KEY

Tests
-----

To run all tests:

.. code-block:: bash

    python -m pytest --cov=credsweeper --cov-report=term-missing -s tests/

To run only tests independent from external api:

.. code-block:: bash

    python -m pytest -m "not api_validation" --cov=credsweeper --cov-report=term-missing -s tests/

Use as a python library
-----------------------

Minimal example for scanning line list:

.. code-block:: python

    from credsweeper import CredSweeper, StringContentProvider


    to_scan = ["line one", "password='in_line_2'"]
    cred_sweeper = CredSweeper()
    provider = StringContentProvider(to_scan)
    results = cred_sweeper.file_scan(provider)
    for r in results:
        print(r)

.. code-block::

    rule: Password / severity: medium / line_data_list: [line: 'password='in_line_2'' / line_num: 2 / path:  / value: 'in_line_2' / entropy_validation: False] / api_validation: NOT_AVAILABLE / ml_validation: NOT_AVAILABLE

Minimal example for scanning bytes:

.. code-block:: python

    from credsweeper import CredSweeper, ByteContentProvider


    to_scan = b"line one\npassword='in_line_2'"
    cred_sweeper = CredSweeper()
    provider = ByteContentProvider(to_scan)
    results = cred_sweeper.file_scan(provider)
    for r in results:
        print(r)

.. code-block::

    rule: Password / severity: medium / line_data_list: [line: 'password='in_line_2'' / line_num: 2 / path:  / value: 'in_line_2' / entropy_validation: False] / api_validation: NOT_AVAILABLE / ml_validation: NOT_AVAILABLE


Minimal example for the ML validation:

.. code-block:: python

    from credsweeper import CredSweeper, StringContentProvider, MlValidator, ThresholdPreset


    to_scan = ["line one", "secret='fgELsRdFA'", "secret='template'"]
    cred_sweeper = CredSweeper()
    provider = StringContentProvider(to_scan)

    # You can select lower or higher threshold to get more or less reports respectively
    threshold = ThresholdPreset.medium
    validator = MlValidator(threshold=threshold)

    results = cred_sweeper.file_scan(provider)
    for candidate in results:
        # For each results detected by a CredSweeper, you can validate them using MlValidator
        is_credential, with_probability = validator.validate(candidate)
        if is_credential:
            print(candidate)

Note that `"secret='template'"` is not reported due to failing check by the `MlValidator`.

.. code-block::

    rule: Secret / severity: medium / line_data_list: [line: 'secret='fgELsRdFA'' / line_num: 2 / path:  / value: 'fgELsRdFA' / entropy_validation: False] / api_validation: NOT_AVAILABLE / ml_validation: NOT_AVAILABLE

Benchmark
---------

We have a dataset for testing credential scanners that called `CredData <https://github.com/Samsung/CredData>`_. If you want to test CredSweeper with this dataset please check `here <https://github.com/Samsung/CredData/blob/main/README.md#benchmark>`_.

Configurations
--------------

.. toctree::
   :maxdepth: 1

   apps_config

.. toctree::
   :maxdepth: 1

   rules_config
