#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

NAME="${1:-}"
[[ -n "$NAME" ]] || { echo "Usage: mkchick <name>"; exit 1; }

exec "$SCRIPT_DIR/chick.sh" create "$NAME"