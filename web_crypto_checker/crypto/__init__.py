"""Cryptographic primitives and encodings, implemented here to avoid a dependency.

For now this holds the ASN.1/DER reader the X.509 parser is built on. The
handshake primitives (HKDF, RSA and ECDSA verification for chain validation)
join it as the phases that need them land.
"""
