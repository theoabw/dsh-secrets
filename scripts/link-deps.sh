#!/usr/bin/env bash
# Link the running dsh installation's @deepseek-ai packages into this repo's
# node_modules, so the plugin's external imports resolve at runtime and tsc can
# read the host type declarations. Re-run after `pnpm install` or a dsh upgrade.
#
# The installation is found by DSH_INSTALL_DIR when set, otherwise from the
# global npm root that holds the dsh CLI.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

candidate() {
  local install="$1"
  if [ -d "$install/node_modules/@deepseek-ai" ]; then
    echo "$install/node_modules/@deepseek-ai"
    return 0
  fi
  return 1
}

TARGET=""
if [ -n "${DSH_INSTALL_DIR:-}" ]; then
  TARGET="$(candidate "$DSH_INSTALL_DIR")" || true
fi
if [ -z "$TARGET" ]; then
  GLOBAL_ROOT="$(npm root -g 2>/dev/null || true)"
  if [ -n "$GLOBAL_ROOT" ]; then
    TARGET="$(candidate "$GLOBAL_ROOT/@deepseek-ai/dsh")" || true
  fi
fi
if [ -z "$TARGET" ]; then
  echo "error: could not find a dsh installation; set DSH_INSTALL_DIR to the @deepseek-ai/dsh package directory" >&2
  exit 1
fi

mkdir -p "$ROOT/node_modules"
ln -sfn "$TARGET" "$ROOT/node_modules/@deepseek-ai"
echo "linked $ROOT/node_modules/@deepseek-ai -> $TARGET"
