#!/usr/bin/env bash
# Compile + run the MA3 reference driver.
# Requires lib/ to contain the MA3 jars (see reference/README.md).
set -euo pipefail
cd "$(dirname "$0")"

export PATH="/opt/homebrew/opt/openjdk@21/bin:$PATH"

mkdir -p build out

# Docker OCSP ayakta ise leaf için bir BasicOCSPResponse kapsülü üret.
OCSP_URL="${TR_ESIGN_TEST_OCSP_URL:-http://127.0.0.1:18080/ocsp}"
if [ -f docker-ocsp/ca/int.crt ] && [ -f docker-ocsp/ca/leaf.crt ]; then
  openssl ocsp \
    -issuer docker-ocsp/ca/int.crt \
    -cert docker-ocsp/ca/leaf.crt \
    -url "$OCSP_URL" \
    -respout docker-ocsp/ca/leaf.ocsp.der \
    -noverify >/dev/null 2>&1 || true
fi

CP="lib/*"
javac --release 21 -cp "$CP" -d build driver/Ma3Ref.java
cd build
java -cp ".:../lib/*" Ma3Ref
