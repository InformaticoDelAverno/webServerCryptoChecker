"""The certificate / PKI-validation stack.

One subpackage, one concern: everything about the X.509 certificate a server
presents and whether it can be trusted. The certificate is parsed by hand from
DER and its chain verified up to a root (``certificates.py``); the key is
checked against ROCA (``roca.py``); the embedded SCTs are verified against known
Certificate Transparency logs (``ct.py``); and revocation is asked over the
network, and authenticated, by OCSP (``ocsp.py``) and CRL (``crl.py``). No
dependency is pulled in to do any of it -- the same rule the TLS engine follows.
"""
