#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
node "$ROOT/scripts/generate.mjs" --check
node "$ROOT/scripts/verify.mjs"
