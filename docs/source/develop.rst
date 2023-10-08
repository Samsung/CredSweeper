Develop
=======

Tests
-----

To run all tests:

.. code-block:: bash

    python -m pytest -s tests/

To run only tests independent from external api:

.. code-block:: bash

    python -m pytest -m "not api_validation_test" -s tests/

Benchmark
---------

We have a dataset for testing credential scanners that called `CredData <https://github.com/Samsung/CredData>`_. If you want to test CredSweeper with this dataset please check `here <https://github.com/Samsung/CredData/blob/main/README.md#benchmark>`_.
