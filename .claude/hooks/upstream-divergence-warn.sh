#!/usr/bin/env bash
# PreToolUse: warn (but not block) when editing core upstream files.
# Authorizer is a third-party project — local changes should be minimal and reviewed against upstream.

set -euo pipefail

INPUT="$(cat)"
FILE_PATH=$(printf '%s' "$INPUT" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("tool_input",{}).get("file_path",""))' 2>/dev/null || echo "")

[ -z "$FILE_PATH" ] && exit 0

# Sensitive core files
case "$FILE_PATH" in
  */cmd/root.go|*/internal/storage/db/sql/*|*/internal/graph/schema.graphqls|*/internal/graphql/*)
    # Warn, do not block (exit 0). The hook just prints to stderr — Claude sees the warning and decides.
    echo "WARN: editing upstream Authorizer core file: $FILE_PATH" >&2
    echo "  Verify the change is necessary for Journez integration and not duplicating an upstream feature." >&2
    echo "  If you're tracking upstream, document the divergence in CLAUDE.md." >&2
    ;;
esac

exit 0
