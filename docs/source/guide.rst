How To Use
==========

Run
---

Get all argument list:

.. code-block:: bash

    python -m credsweeper --help


.. code-block:: text

    usage: python -m credsweeper [-h] (--path PATH [PATH ...] | --diff_path PATH [PATH ...] | --export_config [PATH] | --export_log_config [PATH])
                             [--rules PATH] [--severity SEVERITY] [--config PATH] [--log_config PATH] [--denylist PATH]
                             [--find-by-ext] [--depth POSITIVE_INT] [--no-filters] [--doc] [--ml_threshold FLOAT_OR_STR]
                             [--ml_batch_size POSITIVE_INT] [--ml_config PATH] [--ml_model PATH] [--ml_providers STR]
                             [--jobs POSITIVE_INT] [--skip_ignored] [--save-json [PATH]]
                             [--save-xlsx [PATH]] [--color] [--hashed] [--subtext] [--sort] [--log LOG_LEVEL]
                             [--size_limit SIZE_LIMIT]
                             [--banner] [--version]
    options:
      -h, --help            show this help message and exit
      --path PATH [PATH ...]
                            file or directory to scan
      --diff_path PATH [PATH ...]
                            git diff file to scan
      --export_config [PATH]
                            exporting default config to file (default: config.json)
      --export_log_config [PATH]
                            exporting default logger config to file (default: log.yaml)
      --rules PATH          path of rule config file (default: credsweeper/rules/config.yaml). severity:['critical', 'high', 'medium', 'low', 'info'] type:['keyword', 'pattern', 'pem_key', 'multi']
      --severity SEVERITY   set minimum level for rules to apply ['critical', 'high', 'medium', 'low', 'info'](default: 'Severity.INFO', case insensitive)
      --config PATH         use custom config (default: built-in)
      --log_config PATH     use custom log config (default: built-in)
      --denylist PATH       path to a plain text file with lines or secrets to ignore
      --find-by-ext         find files by predefined extension
      --depth POSITIVE_INT  additional recursive search in data (experimental)
      --no-filters          disable filters
      --doc                 document-specific scanning
      --ml_threshold FLOAT_OR_STR
                            setup threshold for the ml model. The lower the threshold - the more credentials will be reported. Allowed values: float between 0 and 1, or any of ['lowest', 'low', 'medium', 'high',
                            'highest'] (default: medium)
      --ml_batch_size POSITIVE_INT, -b POSITIVE_INT
                            batch size for model inference (default: 16)
      --ml_config PATH      use external config for ml model
      --ml_model PATH       use external ml model
      --ml_providers STR    comma separated list of providers for onnx (CPUExecutionProvider is used by default)
      --jobs POSITIVE_INT, -j POSITIVE_INT
                            number of parallel processes to use (default: 1)
      --skip_ignored        parse .gitignore files and skip credentials from ignored objects
      --save-json [PATH]    save result to json file (default: output.json)
      --save-xlsx [PATH]    save result to xlsx file (default: output.xlsx)
      --color, -C           print results with colorization
      --hashed              line, variable, value will be hashed in output
      --subtext             line text will be stripped in 160 symbols but value and variable are kept
      --sort                enable output sorting
      --log LOG_LEVEL, -l LOG_LEVEL
                            provide logging level of ['DEBUG', 'INFO', 'WARN', 'WARNING', 'ERROR', 'FATAL', 'CRITICAL', 'SILENCE'](default: 'warning', case insensitive)
      --size_limit SIZE_LIMIT
                            set size limit of files that for scanning (eg. 1GB / 10MiB / 1000)
      --banner              show version and crc32 sum of CredSweeper files at start
      --version, -V         show program's version number and exit

.. note::
    Validation by `ML model classifier  <https://credsweeper.readthedocs.io/en/latest/overall_architecture.html#ml-validation>`_ is used to reduce False Positives (by far), but might increase False negatives and execution time.
    You may change system sensitivity by modifying --ml_threshold argument. Increasing threshold will decrease the number of alerts.
    Setting `--ml_threshold 0` will turn ML off and will maximize the number of alerts.

    Typical False Positives: `password = "template_password"`

.. note::
    CredSweeper has experimental option `--depth` to scan files when taking into account a knowledge about data formats:
        - supported containers (tar, zip, gzip, bzip2)
        - base64 encoded data
        - represent text (xml, json, yaml etc.) as a structure and combine keys with values before analysis
        - parse python source files with builtin ast engine

    Pay attention: reported line number of found credential may be not actual in original data, but "info" field may help to understand how the credential was found.

Get output as JSON file:

.. code-block:: bash

    python -m credsweeper --path tests/samples/password.gradle --save-json output.json

To check JSON file run:

.. code-block:: bash

    cat output.json


.. code-block:: json

    [
        {
            "rule": "Password",
            "severity": "medium",
            "confidence": "moderate",
            "ml_probability": 0.9857242107391357,
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
                    "variable_start": 0,
                    "variable_end": 8,
                    "entropy_validation":
                    {
                        "iterator": "BASE64STDPAD_CHARS",
                        "entropy": 2.120589933192232,
                        "valid": false
                    }
                }
            ]
        }
    ]

Get CLI output only:

.. code-block:: bash

    python -m credsweeper --path tests/samples/password.gradle


.. code-block:: text

    rule: Password | severity: medium | confidence: moderate | ml_probability: 0.9857242107391357 | line_data_list: [line: 'password = "cackle!"' | line_num: 1 | path: tests/samples/password.gradle | value: 'cackle!' | entropy_validation: BASE64STDPAD_CHARS 2.120590 False]


Exclude outputs using CLI:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you want to remove some values from report (e.g. known public secrets):
create text files with lines or values you want to remove and add it using `--denylist` argument.
Space-like characters at left and right will be ignored.

.. code-block:: bash

    $ python -m credsweeper --path tests/samples/password.gradle --denylist list.txt
    Detected Credentials: 0
    Time Elapsed: 0.07523202896118164s
    $ cat list.txt
    cackle!
      password = "cackle!"

Exclude outputs using config:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Edit ``exclude`` part of the config file.
Default config can be generated using ``python -m credsweeper --export_config place_to_save.json``
or can be found in ``credsweeper/secret/config.json``.
Space-like characters at left and right will be ignored.

.. code-block:: json

    "exclude": {
        "lines": ["   password = \"cackle!\" "],
        "values": ["cackle!"]
    }

Then specify your config in CLI:

.. code-block:: bash

    $ python -m credsweeper --path tests/samples/password.gradle --config my_cfg.json
    Detected Credentials: 0
    Time Elapsed: 0.07152628898620605s

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

.. code-block:: text

    rule: Password | severity: medium | confidence: moderate | ml_probability: 0.9857242107391357 | line_data_list: [line: 'password = "cackle!"' | line_num: 1 | path:  | value: 'cackle!' | entropy_validation: BASE64STDPAD_CHARS 2.120590 False]

Minimal example for scanning bytes:

.. code-block:: python

    from credsweeper import CredSweeper, ByteContentProvider


    to_scan = b"line one\npassword='cackle!'"
    cred_sweeper = CredSweeper()
    provider = ByteContentProvider(to_scan)
    results = cred_sweeper.file_scan(provider)
    for r in results:
        print(r)

.. code-block:: text

    rule: Password | severity: medium | confidence: moderate | ml_probability: 0.9857242107391357 | line_data_list: [line: 'password = "cackle!"' | line_num: 2 | path:  | value: 'cackle!' | entropy_validation: BASE64STDPAD_CHARS 2.120590 False]


Minimal example for the ML validation:

.. code-block:: python

    from credsweeper import CredSweeper, StringContentProvider, MlValidator, ThresholdPreset


    to_scan = ["line one", "password='cackle!'", "secret='template'"]
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

.. code-block:: text

    rule: Password | severity: medium | confidence: moderate | ml_probability: 0.9857242107391357 | line_data_list: [line: 'password = "cackle!"' | line_num: 2 | path:  | value: 'cackle!' | entropy_validation: BASE64STDPAD_CHARS 2.120590 False]

Configurations
--------------

.. toctree::
   :maxdepth: 1

   apps_config

.. toctree::
   :maxdepth: 1

   rules_config
