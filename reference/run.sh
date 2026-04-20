#!/usr/bin/env bash
# Compile + run the MA3 reference driver.
# Requires lib/ to contain the MA3 jars (see reference/README.md).
set -euo pipefail
cd "$(dirname "$0")"

export PATH="/opt/homebrew/opt/openjdk@21/bin:$PATH"

mkdir -p build out

CP="lib/*"
javac --release 21 -cp "$CP" -d build driver/Ma3Ref.java
cd build
java -cp ".:../lib/*" Ma3Ref
