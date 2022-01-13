How To Use
==========

Run
---

Get all argument list:

.. code-block:: bash

    python -m credsweeper --help


.. code-block::

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

Get output as JSON file:

.. code-block:: bash

    python -m credsweeper --ml_validation --path tests/samples/password --save-json output.json


.. code-block:: ruby

    rule: Password / severity: medium / line_data_list: [line : 'password = "cackle!"' / line_num : 1 / path : tests/samples/password / entropy_validation: False] / api_validation: NOT_AVAILABLE / ml_validation: VALIDATED_KEY

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
