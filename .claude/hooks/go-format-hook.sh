#!/usr/bin/env bash
# Mirror the workspace Go format hook.
set -euo pipefail

INPUT="$(cat)"
FILE_PATH=$(printf '%s' "$INPUT" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("tool_input",{}).get("file_path",""))' 2>/dev/null || echo "")

[ -z "$FILE_PATH" ] && exit 0
case "$FILE_PATH" in
  *.go) ;;
  *) exit 0 ;;
esac
[ ! -f "$FILE_PATH" ] && exit 0

command -v gofmt >/dev/null 2>&1 && gofmt -w "$FILE_PATH" || true
command -v goimports >/dev/null 2>&1 && goimports -w "$FILE_PATH" || true

exit 0
