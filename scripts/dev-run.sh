#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -f .env ]]; then
  # Only source a local file you trust: this is shell code, not a dotenv parser.
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

if ! command -v cargo >/dev/null 2>&1 && [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

# Local development should not listen on every network interface by default.
export RELAY_ADDR="${RELAY_ADDR:-127.0.0.1:8080}"
exec cargo run --release --locked
