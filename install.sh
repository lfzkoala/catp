#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$REPO_DIR/catp-plugin"

echo "==> Installing dependencies..."
cd "$REPO_DIR"
NODE_ENV=development npm install --silent

echo "==> Building catp-plugin..."
cd "$PLUGIN_DIR"
"$REPO_DIR/node_modules/.bin/tsc"

echo "==> Installing catp binary..."
# Prefer ~/.local/bin (user-local, no sudo); fall back to /usr/local/bin
mkdir -p "$HOME/.local/bin"
if [[ ":$PATH:" == *":$HOME/.local/bin:"* ]]; then
  BIN_DIR="$HOME/.local/bin"
else
  BIN_DIR="/usr/local/bin"
fi

DIST_CLI="$PLUGIN_DIR/dist/cli.js"
chmod +x "$DIST_CLI"
ln -sf "$DIST_CLI" "$BIN_DIR/catp"

echo "==> catp installed to $BIN_DIR/catp"
echo ""
echo "Next steps:"
echo ""
echo "1. Add CATP hooks to ~/.claude/settings.json:"
echo ""
cat <<'JSON'
{
  "hooks": {
    "PreToolUse": [{
      "matcher": ".*",
      "command": "catp hook pre"
    }],
    "PostToolUse": [{
      "matcher": ".*",
      "command": "catp hook post"
    }]
  }
}
JSON
echo ""
echo "2. In your project directory:"
echo "   catp init      # create catp-policy.toml"
echo "   catp validate  # check policy syntax"
echo "   catp log show  # view audit log"
