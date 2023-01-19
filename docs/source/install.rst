Installation
============

Currently `CredSweeper` requires the following prerequisites:

* Python version 3.8, 3.9, 3.10

.. note::
    We recommend to use credsweeper in a separate virtual enviroment. Some heave dependencies as Tensorflow
    might create a conflict with other dependencies othervise

Via pip
-------

.. code-block:: bash

    pip install credsweeper

.. note::
    If you didn't installed git, you may encounter the following error:
    
    .. code-block:: bash

        ...

        All git commands will error until this is rectified.

        This initial warning can be silenced or aggravated in the future by setting the
        $GIT_PYTHON_REFRESH environment variable. Use one of the following values:
            - quiet|q|silence|s|none|n|0: for no warning or exception
            - warn|w|warning|1: for a printed warning
            - error|e|raise|r|2: for a raised exception

        Example:
            export GIT_PYTHON_REFRESH=quiet

    If so, please install git.

    .. code-block:: bash

        sudo apt install git

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
