#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build/classes"
JAR_PATH="$ROOT_DIR/dist/burp-image-viewer.jar"
CLASSPATH="$ROOT_DIR/lib/burp-extender-api.jar"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR" "$(dirname "$JAR_PATH")"

find "$ROOT_DIR/src/main/java" -name "*.java" -print0 \
  | xargs -0 javac -cp "$CLASSPATH" -d "$BUILD_DIR"

jar cfe "$JAR_PATH" burp.BurpExtender -C "$BUILD_DIR" .
echo "Built $JAR_PATH"
