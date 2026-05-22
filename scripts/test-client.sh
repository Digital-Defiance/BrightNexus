#!/bin/bash
# Run tests for the enclave-bridge-client TypeScript library
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CLIENT_DIR="$PROJECT_ROOT/enclave-bridge-client"

TEST_TYPE="${1:-all}"

cd "$CLIENT_DIR"

# Ensure dependencies are installed
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
fi

run_unit_tests() {
    echo "🧪 Running Node.js Unit Tests..."
    npm run test:unit
}

run_integration_tests() {
    echo "🔗 Running Node.js Integration Tests..."
    npm run test:integration
}

run_e2e_tests() {
    echo "🌐 Running End-to-End Tests..."
    echo "   ⚠️  Note: Requires BrightNexus app to be running"
    npm run test:e2e
}

case "$TEST_TYPE" in
    unit)
        run_unit_tests
        ;;
    integration)
        run_integration_tests
        ;;
    e2e)
        run_e2e_tests
        ;;
    all)
        run_unit_tests
        echo ""
        run_integration_tests
        ;;
    full)
        run_unit_tests
        echo ""
        run_integration_tests
        echo ""
        run_e2e_tests
        ;;
    *)
        echo "Usage: $0 [unit|integration|e2e|all|full]"
        echo "  unit        - Run unit tests only"
        echo "  integration - Run integration tests only"
        echo "  e2e         - Run end-to-end tests (requires running app)"
        echo "  all         - Run unit + integration tests (default)"
        echo "  full        - Run all tests including e2e"
        exit 1
        ;;
esac

echo ""
echo "✅ Node.js tests completed!"
