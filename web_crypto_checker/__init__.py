"""webServerCryptoChecker -- audit the cryptography offered by web servers.

The package is deliberately dependency-free so it can be dropped onto any host
that has a reasonably modern Python 3 interpreter. The TLS records and the
cryptography needed to enumerate what a server offers live in this package, not
in OpenSSL, so the same probe can reach a legacy server a system OpenSSL would
refuse to speak to.

Public entry points:
    web_crypto_checker.cli.main          -- command line interface
    web_crypto_checker.targets           -- how a target specification is parsed
"""

from __future__ import annotations

__all__ = ["PRODUCT_NAME", "USER_AGENT", "__version__"]

__version__ = "0.1.0"

PRODUCT_NAME = "webServerCryptoChecker"

#: Identification string sent on the HTTP layer. It is intentionally
#: recognisable so administrators can correlate a scan with their access logs.
USER_AGENT = f"webServerCryptoChecker/{__version__}"
