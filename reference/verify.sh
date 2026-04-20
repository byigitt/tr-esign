#!/usr/bin/env bash
# MA3 ile bir XAdES dosyasını doğrula. Çıkış 0 = valid.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="/opt/homebrew/opt/openjdk@21/bin:$PATH"
mkdir -p build
javac --release 21 -cp "lib/*" -d build driver/Ma3Verify.java 2>/dev/null || \
  javac --release 21 -cp "lib/*" -d build driver/Ma3Verify.java
ARG="${1:-reference/out/enveloping-bes.xml}"
# resolve arg relative to repo root (caller's perspective)
[[ "$ARG" = /* ]] || ARG="$(cd .. && pwd)/$ARG"
cd build
java -cp ".:../lib/*" Ma3Verify "$ARG"
