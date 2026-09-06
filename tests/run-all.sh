#!/bin/sh
# Run every overAuth test (needs node 18+ and python3; no npm packages, no network).
set -e
cd "$(dirname "$0")/.."
echo "=== overauth.js (the SDK a developer embeds) ==="
node tests/overauth.test.js
echo "=== overauth.html (the developer console) ==="
node tests/console.test.js
echo "=== overauth-demo.html (a pretend third-party site) ==="
node tests/demo.test.js
echo "All overAuth test suites passed."
