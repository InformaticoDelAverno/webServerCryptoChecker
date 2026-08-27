"""The application-layer protocols the scanner probes over the handshake.

Once the TLS (or QUIC) handshake is done, these modules speak what runs on top
of it and report what the server negotiates: HTTP/2 (``http2.py``) with its
header compression (``hpack.py``), gRPC (``grpc.py``), secure WebSocket
(``websocket.py``), Server-Sent Events (``sse.py``), and mutual-TLS client
authentication (``mtls.py``). Each rides the same hand-rolled TLS 1.3/1.2
transport, adds no dependency, and turns what it sees into findings.
"""
