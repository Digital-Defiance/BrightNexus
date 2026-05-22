#!/bin/bash
# Run all tests for BrightNexus
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🧪 Running all BrightNexus tests..."
echo ""

# Run Swift tests
"$SCRIPT_DIR/test-app.sh" all
echo ""

# Run node tests
echo ""
echo "Running Node.js tests"
npm run test:client
npm run test:e2e

echo "════════════════════════════════════════"
echo "✅ All tests completed successfully!"
echo "════════════════════════════════════════"
