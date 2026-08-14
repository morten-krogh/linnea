#!/usr/bin/env bash
# Certbot deploy hook: copy a freshly issued/renewed certificate into
# linnea's cert directory and reload the server. Certs are read once, at
# startup — but a reload (SIGUSR2) re-execs the master in place, which
# re-reads the config and the certificates, so the new chain takes effect
# without dropping a single connection: the listening sockets survive the
# exec, new workers come up on them, and the old ones drain their in-flight
# requests. Runs as root on every successful issuance or renewal.
#
# Install (one time):
#   sudo install -m 0755 config/certbot-deploy-hook.sh \
#       /etc/letsencrypt/renewal-hooks/deploy/linnea.sh
#
# Certbot sets RENEWED_LINEAGE to /etc/letsencrypt/live/<domain>.
set -eu
domain=$(basename "$RENEWED_LINEAGE")
dir=/etc/linnea/certs/$domain
install -d -m 0755 -o root -g root "$dir"
# root owns them; the service reads the key through its group. 0640 rather than
# 0600 because the running server is linnea-svc, not root -- and 0644, which the
# initial hand-copied key actually had on the box until 2026-08-14, means every
# local account can read the private key.
install -m 0644 -o root -g linnea-svc "$RENEWED_LINEAGE/fullchain.pem" "$dir/fullchain.pem"
install -m 0640 -o root -g linnea-svc "$RENEWED_LINEAGE/privkey.pem" "$dir/privkey.pem"
systemctl reload linnea
