#!/bin/bash
# Build the BrightNexus macOS application
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "🔨 Building BrightNexus macOS App..."
echo "   Project: $PROJECT_ROOT/BrightNexus.xcodeproj"

cd "$PROJECT_ROOT"

# Clean previous build (optional, comment out for faster incremental builds)
# rm -rf build

# Build Release configuration
xcodebuild \
    -project BrightNexus.xcodeproj \
    -scheme BrightNexus \
    -configuration Release \
    -derivedDataPath ./build \
    ONLY_ACTIVE_ARCH=NO \
    build 2>&1 | grep -E "(BUILD|error:|warning:|\*\*)" || true

if [ -d "build/Build/Products/Release/Enclave.app" ]; then
    echo ""
    echo "✅ Build successful!"
    echo "   App: $PROJECT_ROOT/build/Build/Products/Release/Enclave.app"
else
    echo ""
    echo "❌ Build failed!"
    exit 1
fi
