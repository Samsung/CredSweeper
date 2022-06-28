Installation
============

Currently `CredSweeper` requires the following prerequisites:

* Python version 3.7, 3.8, 3.9

.. note::
    We recommend to use credsweeper in a separate virtual enviroment. Some heave dependencies as Tensorflow
    might create a conflict with other dependencies othervise

Via pip
-------

.. code-block:: bash

    pip install credsweeper

.. note::
    Allows to use `ML model classifier <https://credsweeper.readthedocs.io/en/latest/overall_architecture.html#ml-validation>`_
    to validate credential candidates, but requires setup of additional packages: numpy, scikit-learn and tensorflow.

Via git clone (dev install)
---------------------------

.. code-block:: bash

    git clone https://github.com/Samsung/CredSweeper.git
    cd CredSweeper
    # Annotate "numpy", "scikit-learn" and "tensorflow" if you don't want to use the ML validation feature.
    pip install -qr requirements.txt
