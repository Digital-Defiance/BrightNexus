#!/bin/bash
# Build and run the BrightNexus macOS application
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_PATH="$PROJECT_ROOT/build/Build/Products/Release/Enclave.app"

# Build first if needed
if [ ! -d "$APP_PATH" ] || [ "$1" = "--rebuild" ]; then
    "$SCRIPT_DIR/build-app.sh"
fi

echo ""
echo "🚀 Launching BrightNexus..."

# Kill existing instance if running
pkill -f "Enclave.app" 2>/dev/null || true
sleep 1

# Launch the app
open "$APP_PATH"

echo "✅ BrightNexus is running!"
echo "   Socket path will appear in the app's sidebar"
