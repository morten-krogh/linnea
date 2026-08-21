#!/usr/bin/env bash
# Deploy the linnea DEMO PAGE (this directory) to the web root. This is the
# static site served at linnea.amberbio.com -- NOT the linnea server. See
# README.md. The gallery images and video are large static assets that live in
# the web root and are not tracked here; this only touches the page source.
set -eu

WEBROOT=${1:-/var/www/linnea}
here=$(cd "$(dirname "$0")" && pwd)

[ -d "$WEBROOT" ] || { echo "deploy: web root does not exist: $WEBROOT" >&2; exit 1; }
command -v brotli >/dev/null || { echo "deploy: brotli not found" >&2; exit 1; }
command -v gzip   >/dev/null || { echo "deploy: gzip not found" >&2; exit 1; }

# The page source.
for f in index.html app.js style.css favicon.ico; do
    install -m 0644 "$here/$f" "$WEBROOT/$f"
done

# Regenerate the precompressed variants the server content-negotiates. Written
# AFTER their sources so each is newer -- linnea serves the newer of the two.
brotli -f -c "$WEBROOT/index.html" > "$WEBROOT/index.html.br"
brotli -f -c "$WEBROOT/app.js"     > "$WEBROOT/app.js.br"
gzip   -9 -c "$WEBROOT/style.css"  > "$WEBROOT/style.css.gz"

# ...and confirm each decompresses back to exactly its source, so a browser on
# the compressed path and one on the plain path can never get different bytes.
brotli -dc "$WEBROOT/index.html.br" | cmp -s - "$WEBROOT/index.html" || { echo "deploy: index.html.br mismatch" >&2; exit 1; }
brotli -dc "$WEBROOT/app.js.br"     | cmp -s - "$WEBROOT/app.js"     || { echo "deploy: app.js.br mismatch"     >&2; exit 1; }
gzip   -dc "$WEBROOT/style.css.gz"  | cmp -s - "$WEBROOT/style.css"  || { echo "deploy: style.css.gz mismatch"  >&2; exit 1; }

echo "deployed the demo page to $WEBROOT (no reload needed — files are opened per request)"
