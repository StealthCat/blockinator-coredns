#!/usr/bin/env bash
set -euo pipefail
# Compile the plugin into upstream CoreDNS with policy checks before caches,
# rewrites, and answer-producing plugins. Build directory is disposable.
plugin_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source_dir="$plugin_root/build/coredns-source"
if [ -e "$source_dir" ]; then
  echo "Remove or move build/coredns-source before rebuilding." >&2
  exit 1
fi
mkdir -p "$plugin_root/build"
git clone --depth 1 --branch v1.14.7 https://github.com/coredns/coredns.git "$source_dir"
cd "$source_dir"
# Place immediately before 'local', preserving error and query logging above it.
sed -i '/^local:local$/i blockinator:github.com/StealthCat/blockinator-coredns' plugin.cfg
grep -q '^blockinator:' plugin.cfg
go mod edit -require=github.com/StealthCat/blockinator-coredns@v0.0.0
go mod edit "-replace=github.com/StealthCat/blockinator-coredns=$plugin_root"
go generate
go mod tidy
go build -o "$plugin_root/build/coredns" .
"$plugin_root/build/coredns" -plugins | grep -x 'blockinator'
