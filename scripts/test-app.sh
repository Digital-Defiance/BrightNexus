#!/bin/bash
# Run tests for the BrightNexus macOS application
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

TEST_TYPE="${1:-all}"

cd "$PROJECT_ROOT"

run_unit_tests() {
    echo "🧪 Running Swift Unit Tests..."
    xcodebuild test \
        -project BrightNexus.xcodeproj \
        -scheme BrightNexus \
        -destination 'platform=macOS' \
        -testPlan EnclaveTests \
        -derivedDataPath ./build \
        2>&1 | grep -E "(Test Case|passed|failed|error:|\*\*)" || true
}

run_ui_tests() {
    echo "🖥️  Running Swift UI Tests..."
    xcodebuild test \
        -project BrightNexus.xcodeproj \
        -scheme BrightNexus \
        -destination 'platform=macOS' \
        -testPlan EnclaveUITests \
        -derivedDataPath ./build \
        2>&1 | grep -E "(Test Case|passed|failed|error:|\*\*)" || true
}

case "$TEST_TYPE" in
    unit)
        run_unit_tests
        ;;
    ui)
        run_ui_tests
        ;;
    all)
        run_unit_tests
        echo ""
        run_ui_tests
        ;;
    *)
        echo "Usage: $0 [unit|ui|all]"
        echo "  unit - Run unit tests only"
        echo "  ui   - Run UI tests only"
        echo "  all  - Run all tests (default)"
        exit 1
        ;;
esac

echo ""
echo "✅ Swift tests completed!"
