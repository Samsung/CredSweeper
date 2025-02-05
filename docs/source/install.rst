Installation
============

Currently `CredSweeper` requires the following prerequisites:

* Python version 3.9, 3.10, 3.11, 3.12

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

Pre-commit git hook
---------------------------
    Install CredSweeper into system and copy ``pre-commit`` file in your ``.git/hooks`` repo.

.. note::
    CredSweeper must be available in current python environment.

.. note::
    pre-commit file context:
.. code-block:: python

    #!/usr/bin/env python
    import io
    import subprocess
    import sys
    
    from credsweeper import CredSweeper
    from credsweeper.common.constants import DiffRowType
    from credsweeper.file_handler.patch_provider import PatchProvider
    
    
    def main() -> int:
        command = ["git", "diff", "--cached"]
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as pipe:
            _stdout, _stderr = pipe.communicate()
            if pipe.returncode:
                print(str(_stdout), flush=True)
                print(str(_stderr), flush=True)
                print(f"{command} EXIT CODE:{pipe.returncode}", flush=True)
                return 1
    
        patch = io.BytesIO(_stdout)
        added = PatchProvider([patch], change_type=DiffRowType.ADDED)
        deleted = PatchProvider([patch], change_type=DiffRowType.DELETED)
    
        credsweeper = CredSweeper()
    
        if credsweeper.run(content_provider=deleted):
            print(f"CREDENTIALS FOUND IN DELETED CONTENT", flush=True)
            # return 1  # <<< UNCOMMENT THE LINE IF YOU WANT TO MANAGE DELETED CREDENTIALS
    
        if credsweeper.run(content_provider=added):
            print(f"CREDENTIALS FOUND IN ADDED CONTENT", flush=True)
            return 1
    
        return 0
    
    
    if __name__ == "__main__":
        sys.exit(main())
