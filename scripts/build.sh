#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"
./gradlew --no-daemon clean jar

mkdir -p dist
cp build/libs/burp-image-viewer-*.jar dist/burp-image-viewer.jar
echo "Built $(cd dist && pwd)/burp-image-viewer.jar"
