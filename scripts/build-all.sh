#!/bin/bash
# Build all components of BrightNexus
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🚀 Building all BrightNexus components..."
echo ""

# Build macOS app
"$SCRIPT_DIR/build-app.sh"
echo ""

# Build TypeScript client
"$SCRIPT_DIR/build-client.sh"
echo ""

echo "════════════════════════════════════════"
echo "✅ All builds completed successfully!"
echo "════════════════════════════════════════"
