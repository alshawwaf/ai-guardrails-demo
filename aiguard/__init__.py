"""AI Guard Demo Kit core (stdlib only, Python 3.8+).

Shared by the ``aiguard`` CLI and the Flask "Gateway Mode" console. The package
imports nothing heavy at import time; import the submodules you need
(``aiguard.redact``, ``aiguard.runlog``, ``aiguard.tlsutil`` ...).
"""

__version__ = "1.0.0"

__all__ = ["__version__"]
