#!/usr/bin/env bash
# Certbot deploy hook: copy a freshly issued/renewed certificate into
# linnea's cert directory and restart the server (certs are read once,
# at startup). Runs as root on every successful issuance or renewal.
#
# Install (one time):
#   sudo install -m 0755 config/certbot-deploy-hook.sh \
#       /etc/letsencrypt/renewal-hooks/deploy/linnea.sh
#
# Certbot sets RENEWED_LINEAGE to /etc/letsencrypt/live/<domain>.
set -eu
domain=$(basename "$RENEWED_LINEAGE")
dir=/home/linnea/certs/$domain
install -d -m 0755 "$dir"
install -m 0644 -o linnea -g linnea "$RENEWED_LINEAGE/fullchain.pem" "$dir/fullchain.pem"
install -m 0600 -o linnea -g linnea "$RENEWED_LINEAGE/privkey.pem" "$dir/privkey.pem"
systemctl restart linnea
