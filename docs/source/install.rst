Installation
============

Currently `CredSweeper` requires the following prerequisites:
 
* Python version 3.7 or greater

Via pip
-------

Without Ml validation feature

.. code-block:: bash

    pip install credsweeper

With Ml validation feature

.. code-block:: bash

    pip install credsweeper[ml]

Via git clone (dev install)
---------------------------

.. code-block:: bash

    git clone https://github.com/Samsung/CredSweeper.git
    cd CredSweeper
    # Annotate "numpy", "scikit-learn", and "tensorflow" if you don't want to use the ML validation feature.
    pip install -qr requirements.txt 