"""The TLS engine.

TLS is spoken by hand here: a
``ClientHello`` is built byte by byte, sent on a plain socket, and the
``ServerHello`` or alert that comes back is parsed. Enumeration never completes
a handshake -- it only needs the server's one choice -- so it can probe a
legacy server a system OpenSSL would refuse to speak to, and it pulls in no
dependency to do it.
"""

from __future__ import annotations

__all__ = ["TlsError"]

from .wire import TlsError
