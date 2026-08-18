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
#
# The three overrides below exist so this script can be RUN and checked without
# root and without a renewal — it is the one piece of the deployment that fires
# unattended, as root, at an hour nobody is watching, and "it looked right" is
# not a good enough reason to trust it. They all default to what production
# wants. See test/certbot_hook_test.sh.
set -eu
: "${LINNEA_CERT_DIR:=/etc/linnea/certs}"
: "${LINNEA_CERT_OWNER:=root:linnea-svc}"
: "${LINNEA_RELOAD:=systemctl reload linnea}"

domain=$(basename "$RENEWED_LINEAGE")
dir=$LINNEA_CERT_DIR/$domain
owner=${LINNEA_CERT_OWNER%%:*}
group=${LINNEA_CERT_OWNER##*:}
install -d -m 0755 "$dir"

# --- the chain to serve: shorter if it can be, whole if it must be ----------
#
# QUIC forbids a server sending more than 3x what it has received before the
# client's address is validated (RFC 9000 8.1). A client Initial is 1200 bytes,
# so the server's whole first flight has to fit in ~3600 or it stalls and waits
# for another client packet — an extra round trip on EVERY cold HTTP/3
# connection, which TCP never pays. Let's Encrypt's default chain is four certs,
# ~3397 bytes of certificate alone, and does not fit. Dropping the trailing
# cross-signed root brings it to ~2257, which does: measured 3 client flights
# down to 2.
#
# Which certificate is droppable is NOT a constant, so this does not hardcode
# "drop the last one and hope". It builds the shorter chain, checks it still
# verifies against this machine's trust store, and serves the FULL chain if it
# does not. That fallback is the point: when Let's Encrypt next reshuffles its
# hierarchy, an unattended renewal quietly goes back to a working four-cert
# chain instead of serving one nothing can validate. The naive trim — down to
# leaf + intermediate, the way most sites run — already fails today, because
# ISRG Root YE is not yet in trust stores.
full=$RENEWED_LINEAGE/fullchain.pem
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
serve=$full

ncerts=$(grep -c '^-----BEGIN CERTIFICATE-----' "$full" || true)
if [ "${ncerts:-0}" -gt 2 ]; then
    awk -v keep=$((ncerts - 1)) '
        /^-----BEGIN CERTIFICATE-----/ { n++ }
        n <= keep { print }' "$full" > "$work/trimmed.pem"
    awk '/^-----BEGIN CERTIFICATE-----/ { n++ } n == 1 { print }' \
        "$work/trimmed.pem" > "$work/leaf.pem"
    awk '/^-----BEGIN CERTIFICATE-----/ { n++ } n > 1  { print }' \
        "$work/trimmed.pem" > "$work/inter.pem"
    if openssl verify -untrusted "$work/inter.pem" "$work/leaf.pem" >/dev/null 2>&1
    then
        serve=$work/trimmed.pem
        echo "linnea deploy hook: serving $((ncerts - 1)) of $ncerts certs" \
             "(trailing root dropped; QUIC handshake fits the amplification limit)"
    else
        echo "linnea deploy hook: the trimmed chain does not verify —" \
             "serving all $ncerts certs unchanged" >&2
    fi
fi

# root owns them; the service reads the key through its group. 0640 rather than
# 0600 because the running server is linnea-svc, not root -- and 0644, which the
# initial hand-copied key actually had on the box until 2026-08-14, means every
# local account can read the private key.
install -m 0644 -o "$owner" -g "$group" "$serve" "$dir/fullchain.pem"
install -m 0640 -o "$owner" -g "$group" "$RENEWED_LINEAGE/privkey.pem" "$dir/privkey.pem"
$LINNEA_RELOAD
