# The web front end of webServerCryptoChecker in a minimal container.
#
# The easiest path is `docker compose up -d --build` / `docker compose down`. By
# hand:
#
#   docker build -t webservercryptochecker-web .
#   # Open by default (no token, no users): anyone who reaches the port uses it
#   # -- the convenient shape on a trusted LAN:
#   docker run --rm -p 8443:8443 webservercryptochecker-web
#   # Closed with a token (every /api request carries X-Auth-Token):
#   docker run --rm -p 8443:8443 \
#       -e WEB_CRYPTO_CHECKER_WEB_TOKEN=a-secret webservercryptochecker-web
#
# Detection plugins and your own roots enter by volumes + variables, like the CLI:
#   -v $PWD/my-plugins:/plugins:ro -e WEB_CRYPTO_CHECKER_WEB_PLUGIN_DIR=/plugins
#   -v $PWD/roots.pem:/roots.pem:ro -e WEB_CRYPTO_CHECKER_WEB_CA_BUNDLE=/roots.pem
#
# The service scans whatever the container can reach: published without a token it
# is an SSRF machine. Use it on an internal network or behind your TLS proxy. For
# public exposure, harden the edge:
#   -e WEB_CRYPTO_CHECKER_WEB_TOKEN=...          (require X-Auth-Token on the API)
#   -e WEB_CRYPTO_CHECKER_WEB_BLOCK_PRIVATE=1    (refuse internal targets)
# and start the container with no route to your private ranges (egress-controlled
# --network), which is the only hard guarantee against SSRF.

FROM python:3.13-alpine

# ca-certificates gives /etc/ssl/cert.pem, the system trust store the scanner
# validates chains against by default (override with WEB_CRYPTO_CHECKER_WEB_CA_BUNDLE
# or switch off with WEB_CRYPTO_CHECKER_WEB_NO_TRUST=1). It is the one OS package;
# the tool itself pulls nothing (its dependencies are empty by design).
RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY pyproject.toml LICENSE README.md ./
COPY web_crypto_checker/ web_crypto_checker/
RUN pip install --no-cache-dir . && adduser -D wcc
USER wcc

EXPOSE 8443
# Liveness over the stdlib only -- the image ships no curl, and needs none.
HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8443/')"

CMD ["python", "-m", "web_crypto_checker.web", "--host", "0.0.0.0", "--port", "8443"]
