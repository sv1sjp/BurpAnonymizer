#!/bin/bash
# Build script for Burp Request Anonymizer Extension
# Requires: JDK 11+

set -e

PROJECT_DIR=.
SRC_DIR="$PROJECT_DIR/src/main/java"
BUILD_DIR="$PROJECT_DIR/build"
JAR_NAME="BurpAnonymizer1.0.3.jar"
echo "Burp Anonymizer Builder v1.0.3 by Dimitris Vagiakakos @sv1sjp"
echo "[*] Cleaning build directory..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/classes"

echo "[*] Compiling Java sources..."
find "$SRC_DIR" -name "*.java" | xargs javac -d "$BUILD_DIR/classes" -source 11 -target 11 -encoding UTF-8

echo "[*] Creating JAR..."
cd "$BUILD_DIR/classes"
jar cf "$PROJECT_DIR/$JAR_NAME" burp/*.class

echo ""
echo "[+] Build successful!"
echo "[+] JAR: $PROJECT_DIR/$JAR_NAME"
echo ""
echo "To install:"
echo "  1. Open Burp Suite"
echo "  2. Go to Extensions -> Installed -> Add"
echo "  3. Extension type: Java"
echo "  4. Select: $PROJECT_DIR/$JAR_NAME"
echo "  5. Click Next"
echo "  Have a nice day :)"
