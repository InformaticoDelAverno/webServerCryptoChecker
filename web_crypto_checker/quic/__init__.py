"""A hand-rolled QUIC/HTTP-3 engine, built up the way the TLS engine was.

QUIC (RFC 9000) is TLS 1.3 (RFC 9001) carried over UDP with its own packet
protection. This package grows in layers: the variable-length integer codec and
the Initial packet keys first, then packet protection, the Initial exchange, and
finally HTTP/3 reachability. Every layer is validated against the RFC 9000/9001
test vectors and, once packets fly, against a real QUIC server.
"""
