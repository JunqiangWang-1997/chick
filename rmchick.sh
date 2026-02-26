#!/usr/bin/env bash
set -euo pipefail
NAME="${1:-}"
[[ -n "$NAME" ]] || { echo "Usage: rmchick <name>"; exit 1; }
incus delete -f "$NAME"
echo "Deleted: $NAME"