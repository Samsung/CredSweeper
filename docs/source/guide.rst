How To Use
==========

Run
---

Get all argument list:

.. code-block:: bash

    python -m credsweeper --help


.. code-block:: text

    usage: python -m credsweeper [-h]
                                 (--path PATH [PATH ...] | --diff_path PATH [PATH ...] | --export_config [PATH] | --export_log_config [PATH])
                                 [--rules PATH] [--severity SEVERITY]
                                 [--config PATH] [--log_config PATH]
                                 [--denylist PATH] [--find-by-ext]
                                 [--depth POSITIVE_INT] [--no-filters] [--doc]
                                 [--ml_threshold FLOAT_OR_STR]
                                 [--ml_batch_size POSITIVE_INT] [--ml_config PATH]
                                 [--ml_model PATH] [--ml_providers STR]
                                 [--jobs POSITIVE_INT] [--thrifty | --no-thrifty]
                                 [--skip_ignored] [--error | --no-error]
                                 [--save-json [PATH]] [--save-xlsx [PATH]]
                                 [--stdout | --no-stdout] [--color | --no-color]
                                 [--hashed | --no-hashed]
                                 [--subtext | --no-subtext] [--sort | --no-sort]
                                 [--log LOG_LEVEL] [--size_limit SIZE_LIMIT]
                                 [--banner] [--version]

    options:
      -h, --help            show this help message and exit
      --path PATH [PATH ...]
                            file or directory to scan
      --diff_path PATH [PATH ...]
                            git diff file to scan
      --export_config [PATH]
                            exporting default config to file (default:
                            config.json)
      --export_log_config [PATH]
                            exporting default logger config to file (default:
                            log.yaml)
      --rules PATH          path of rule config file (default:
                            credsweeper/rules/config.yaml). severity:['critical',
                            'high', 'medium', 'low', 'info'] type:['keyword',
                            'pattern', 'pem_key', 'multi']
      --severity SEVERITY   set minimum level for rules to apply ['critical',
                            'high', 'medium', 'low', 'info'](default:
                            'Severity.INFO', case insensitive)
      --config PATH         use custom config (default: built-in)
      --log_config PATH     use custom log config (default: built-in)
      --denylist PATH       path to a plain text file with lines or secrets to
                            ignore
      --find-by-ext         find files by predefined extension
      --depth POSITIVE_INT  additional recursive search in data (experimental)
      --no-filters          disable filters
      --doc                 document-specific scanning
      --ml_threshold FLOAT_OR_STR
                            setup threshold for the ml model. The lower the
                            threshold - the more credentials will be reported.
                            Allowed values: float between 0 and 1, or any of
                            ['lowest', 'low', 'medium', 'high', 'highest']
                            (default: medium)
      --ml_batch_size POSITIVE_INT, -b POSITIVE_INT
                            batch size for model inference (default: 16)
      --ml_config PATH      use external config for ml model
      --ml_model PATH       use external ml model
      --ml_providers STR    comma separated list of providers for onnx
                            (CPUExecutionProvider is used by default)
      --jobs POSITIVE_INT, -j POSITIVE_INT
                            number of parallel processes to use (default: 1)
      --thrifty, --no-thrifty
                            clear objects after scan to reduce memory consumption
                            (default: True)
      --skip_ignored        parse .gitignore files and skip credentials from
                            ignored objects
      --error, --no-error   produce error code if credentials are found (default:
                            False)
      --save-json [PATH]    save result to json file (default: output.json)
      --save-xlsx [PATH]    save result to xlsx file (default: output.xlsx)
      --stdout, --no-stdout
                            print results to stdout (default: True)
      --color, --no-color   print results with colorization (default: False)
      --hashed, --no-hashed
                            line, variable, value will be hashed in output
                            (default: False)
      --subtext, --no-subtext
                            line text will be stripped in 160 symbols but value
                            and variable are kept (default: False)
      --sort, --no-sort     enable output sorting (default: False)
      --log LOG_LEVEL, -l LOG_LEVEL
                            provide logging level of ['DEBUG', 'INFO', 'WARN',
                            'WARNING', 'ERROR', 'FATAL', 'CRITICAL',
                            'SILENCE'](default: 'warning', case insensitive)
      --size_limit SIZE_LIMIT
                            set size limit of files that for scanning (eg. 1GB /
                            10MiB / 1000)
      --banner              show version and crc32 sum of CredSweeper files at
                            start
      --version, -V         show program's version number and exit

.. note::
    Validation by `ML model classifier  <https://credsweeper.readthedocs.io/en/latest/overall_architecture.html#ml-validation>`_ is used to reduce False Positives (by far), but might increase False negatives and execution time.
    You may change system sensitivity by modifying --ml_threshold argument. Increasing threshold will decrease the number of alerts.
    Setting `--ml_threshold 0` will turn ML off and will maximize the number of alerts.

    Typical False Positives: `password = "template_password"`

.. note::
    CredSweeper includes an experimental `--depth` option that enables scanning with awareness of specific data formats, such as:

        - Compressed files (zip, gzip, bzip2, lzma)
        - Data containers (deb, tar, Docker images, pkcs12, jks)
        - Document rendering (pdf, xls, ods, xlsx, docx, pptx, tm7, mxfile)
        - Base64-encoded content
        - Structured text formats (HTML, XML, JSON, NDJSON, YAML, etc.) - keys and values are combined before analysis
        - Python source files - re-parsed to reconstruct values across all possible formatting variants that could interfere with pattern matching

    **Remark:** The reported line number for a found credential with the option may not correspond to the original file. The `info` field provides context to help you understand how the credential was detected.

Get output as JSON file with deep scan for docker image:

Prepare dockerfile

.. code-block:: docker

    FROM scratch
    ADD tests/samples /

Build, save and scan

.. code-block:: bash

    docker build . --tag test_samples
    docker save test_samples --output test_samples.docker
    python -m credsweeper --path test_samples.docker --save-json output.json --depth 3

Review the report file (output.json):

.. code-block:: json

    [
    ...
        {
            "rule": "Password",
            "severity": "medium",
            "confidence": "moderate",
            "ml_probability": 0.7925280332565308,
            "line_data_list": [
                {
                    "line": "password = 'cackle!'",
                    "line_num": 1,
                    "path": "test_samples.docker",
                    "info": "FILE:test_samples.docker|TAR:blobs/sha256/82a4962c3cfebb62a42c2fd5c120ea0706a9ae66f52f71f957c052c873c60775|TAR:password.gradle|STRUCT|STRING:0|RAW",
                    "variable": "password",
                    "variable_start": 0,
                    "variable_end": 8,
                    "value": "cackle!",
                    "value_start": 12,
                    "value_end": 19,
                    "entropy": 2.52164
                }
            ]
        },
    ...
    ]

Get CLI output only:

.. code-block:: bash

    python -m credsweeper --path tests/samples/password.gradle


.. code-block:: text

    rule: Password | severity: medium | confidence: moderate | ml_probability: 0.9149653911590576 | line_data_list: [path: tests/samples/password.gradle | line_num: 1 | value: 'cackle!' | line: 'password = "cackle!"']


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
