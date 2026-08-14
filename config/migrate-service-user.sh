#!/usr/bin/env bash
#
# One-time migration: move linnea from the `linnea` human account to a dedicated
# `linnea-svc` service identity, and out of /home into system paths.
#
#   RUN AS ROOT:   bash config/migrate-service-user.sh
#
# Why: kill(2) permits a signal only between matching UIDs. While production ran
# as `linnea` -- the same account that owns this repo and runs the test fixtures,
# under the same binary NAME -- a `pkill -x linnea` in a development shell took
# the live site with it. That happened five times on 2026-08-14. A UID boundary
# is enforced by the kernel; remembering not to type it demonstrably is not.
#
# The `linnea` account is added to the linnea-svc GROUP, which grants it read
# access to the config and the logs. That is not a way back in: signals are
# governed by UID, group membership is not.
#
# Nothing is deleted. The old paths under /home are left exactly as they are, so
# rollback is immediate; remove them by hand once you are satisfied (see the end).
#
# Safe to re-run: every step is idempotent.

set -euo pipefail
trap 'echo "FAILED at line $LINENO" >&2' ERR

REPO=/home/linnea/linnea
DOMAIN=linnea.amberbio.com
OLD_ACME=/home/linnea/acme
NEW_ACME=/var/www/acme

say() { printf '\n=== %s\n' "$*"; }
ok()  { printf '    ok  %s\n' "$*"; }

# ---------------------------------------------------------------- preconditions
say "preconditions"
[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
for f in "$REPO/config/linnea.service" "$REPO/config/linnea-api.service" \
         "$REPO/config/linnea-ws.service" "$REPO/config/linnea.logrotate" \
         "$REPO/config/certbot-deploy-hook.sh"; do
    [ -r "$f" ] || { echo "missing $f" >&2; exit 1; }
done
for b in /usr/local/bin/linnea /usr/local/bin/linnea-api /usr/local/bin/linnea-ws; do
    [ -x "$b" ] || { echo "missing $b -- run 'make && make install' first" >&2; exit 1; }
done
[ -r "/home/linnea/certs/$DOMAIN/fullchain.pem" ] || { echo "no cert to copy" >&2; exit 1; }
ok "repo, binaries and certificates present"

# ------------------------------------------------------------ service identity
say "service identity"
getent group linnea-svc >/dev/null || groupadd --system linnea-svc
getent passwd linnea-svc >/dev/null || useradd --system --gid linnea-svc \
    --no-create-home --home-dir /var/lib/linnea --shell /usr/sbin/nologin linnea-svc
usermod -aG linnea-svc linnea
ok "linnea-svc exists; linnea is a member of the linnea-svc group"
echo "    NOTE: that membership reaches a shell only after a fresh login."

# -------------------------------------------------------- directories and data
say "directories and data (copied, never moved -- the originals stay)"
install -d -m 0755 -o root   -g root   /etc/linnea /etc/linnea/certs /var/www "$NEW_ACME"
install -d -m 0755 -o linnea -g linnea /var/www/linnea
install -d -m 0755 -o root   -g root   "/etc/linnea/certs/$DOMAIN"

# systemd creates these from LogsDirectory=/StateDirectory= when the service
# STARTS -- which is too late for the `--test` validation below, and that test
# is the whole point: it must prove the paths work before anything goes live.
# Create them here with exactly the ownership and modes the unit declares
# (LogsDirectoryMode=0755, StateDirectoryMode=0770); systemd adopts them as-is.
install -d -m 0755 -o linnea-svc -g linnea-svc /var/log/linnea
install -d -m 0770 -o linnea-svc -g linnea-svc /var/lib/linnea /var/lib/linnea/spill

cp -a /home/linnea/www/linnea/. /var/www/linnea/
if [ -d "$OLD_ACME" ]; then cp -a "$OLD_ACME/." "$NEW_ACME/"; fi
ok "web root -> /var/www/linnea, acme webroot -> $NEW_ACME"

# 0640, not the 0644 the hand-copied key has had on this box: at 0644 every
# local account can read the TLS private key.
install -m 0644 -o root -g linnea-svc "/home/linnea/certs/$DOMAIN/fullchain.pem" \
        "/etc/linnea/certs/$DOMAIN/fullchain.pem"
install -m 0640 -o root -g linnea-svc "/home/linnea/certs/$DOMAIN/privkey.pem" \
        "/etc/linnea/certs/$DOMAIN/privkey.pem"
ok "certificates -> /etc/linnea/certs ($DOMAIN), private key now 0640"

# ------------------------------------------------------------------ the config
# Embedded rather than copied from the repo: config/linnea-tls.json is still the
# LIVE config of the old layout, and must keep working for a rollback.
say "config -> /etc/linnea/linnea-tls.json"
cat > /etc/linnea/linnea-tls.json <<'JSON'
{
  "log": "/var/log/linnea/linnea.log",
  "error_log": "/var/log/linnea/linnea-error.log",
  "timeout": 60,
  "proxy_timeout": 10,
  "drain_timeout": 10,
  "max_body": 67108864,
  "rate_limit": 200,
  "spill_dir": "/var/lib/linnea/spill",
  "servers": [
    {
      "host": "0.0.0.0",
      "port": 443,
      "hostname": "linnea.amberbio.com",
      "cert": "/etc/linnea/certs/linnea.amberbio.com/fullchain.pem",
      "key": "/etc/linnea/certs/linnea.amberbio.com/privkey.pem",
      "hsts": "max-age=86400",
      "nosniff": 1,
      "locations": [
        { "prefix": "/api", "proxy": "127.0.0.1:7700" },
        { "prefix": "/ws",  "proxy": "127.0.0.1:7701" },
        { "prefix": "/",    "root": "/var/www/linnea" }
      ]
    },
    {
      "host": "0.0.0.0",
      "port": 80,
      "hostname": "linnea.amberbio.com",
      "locations": [
        { "prefix": "/.well-known/acme-challenge", "root": "/var/www/acme" },
        { "prefix": "/", "redirect": "https://linnea.amberbio.com" }
      ]
    }
  ]
}
JSON
chown root:linnea-svc /etc/linnea/linnea-tls.json
chmod 0640            /etc/linnea/linnea-tls.json
ok "installed 0640 root:linnea-svc"

# ------------------------------------------------------------------ unit files
say "unit files (previous versions kept as .bak-MIGRATION)"
for u in linnea linnea-api linnea-ws; do
    dst=/etc/systemd/system/$u.service
    if [ -f "$dst" ]; then cp -a "$dst" "$dst.bak-MIGRATION"; fi
    install -m 0644 "$REPO/config/$u.service" "$dst"
done
systemctl daemon-reload
ok "units installed, daemon reloaded"

# ------------------------------------------------------------------- logrotate
say "logrotate"
if [ -f /etc/logrotate.d/linnea ]; then
    cp -a /etc/logrotate.d/linnea /etc/logrotate.d/linnea.bak-MIGRATION
fi
install -m 0644 "$REPO/config/linnea.logrotate" /etc/logrotate.d/linnea
ok "installed -- now covers linnea-error.log too, which had NO rotation before"

# --------------------------------------------------------------------- certbot
say "certbot"
if [ -d /etc/letsencrypt ]; then
    install -m 0755 "$REPO/config/certbot-deploy-hook.sh" \
            /etc/letsencrypt/renewal-hooks/deploy/linnea.sh
    ok "deploy hook installed (writes to /etc/linnea/certs, key 0640)"
    # The renewal config still names the OLD webroot, which linnea-svc cannot
    # reach. Left unfixed this does not fail today -- it fails at the next
    # renewal, silently, in about two months.
    changed=0
    for f in /etc/letsencrypt/renewal/*.conf; do
        [ -e "$f" ] || continue
        if grep -q "$OLD_ACME" "$f"; then
            cp -a "$f" "$f.bak-MIGRATION"
            sed -i "s#$OLD_ACME#$NEW_ACME#g" "$f"
            echo "    rewrote webroot in $f (backup kept)"
            changed=1
        fi
    done
    if [ "$changed" -eq 0 ]; then
        if grep -rqs "$NEW_ACME" /etc/letsencrypt/renewal/ 2>/dev/null; then
            ok "renewal config already points at $NEW_ACME"
        else
            echo "    no renewal config names $OLD_ACME -- CHECK BY HAND:"
            echo "      grep -rn webroot /etc/letsencrypt/renewal/"
        fi
    fi
else
    echo "    /etc/letsencrypt not present -- skipped"
fi

# ------------------------------------------------- validate BEFORE starting up
say "validating the config as linnea-svc (proves it can read config and certs)"
runuser -u linnea-svc -- /usr/local/bin/linnea --test --config /etc/linnea/linnea-tls.json
ok "config accepted"

# ----------------------------------------------------------------------- start
say "starting services (backends first)"
systemctl restart linnea-api linnea-ws
systemctl restart linnea
sleep 2
systemctl is-active linnea linnea-api linnea-ws || true
ps -C linnea,linnea-api,linnea-ws -o user:12=,pid=,comm= 2>/dev/null | sed 's/^/    /' || true

# ---------------------------------------------------------------- verification
say "verification"
fail=0

for p in linnea linnea-api linnea-ws; do
    u=$(ps -C "$p" -o user:12= 2>/dev/null | head -1 | tr -d ' ' || true)
    [ "$u" = "linnea-svc" ] && ok "$p runs as linnea-svc" \
        || { echo "    FAIL $p runs as '$u'"; fail=1; }
done

# Compare the STATUS, not curl's exit code: curl exits 0 for a 502 as happily
# as for a 200, so "|| fail=1" alone would call a broken backend a success.
http_is() {            # <label> <expected> <curl binary> <extra args...> <url>
    local label=$1 expect=$2; shift 2
    local code; code=$("$@" -sS --max-time 10 -o /dev/null -w '%{http_code}' 2>/dev/null || echo 000)
    if [ "$code" = "$expect" ]; then ok "$label $code"
    else echo "    FAIL $label expected $expect, got $code"; fail=1; fi
}
http_is "h2 " 200 curl --http2 "https://$DOMAIN/"
if [ -x /home/linnea/curl-h3/bin/curl ]; then
    http_is "h3 " 200 /home/linnea/curl-h3/bin/curl --http3-only "https://$DOMAIN/"
fi
http_is "api" 200 curl "https://$DOMAIN/api/random"

# The logs must stay readable from the ordinary account. This is load-bearing,
# not cosmetic: the journal is already closed to a non-root user, and on
# 2026-08-14 these two files were the only evidence available for nine
# unexplained worker deaths.
if runuser -u linnea -- test -r /var/log/linnea/linnea.log; then
    ok "the linnea account can read /var/log/linnea/linnea.log"
else
    echo "    FAIL the linnea account cannot read the access log"; fail=1
fi

# The point of the whole exercise. Tested AS linnea -- as root it would pass
# meaninglessly, because root may signal anything.
MAINPID=$(systemctl show -p MainPID --value linnea)
# Guard the pid: `kill -0 0` signals the whole PROCESS GROUP, so a failed start
# (MainPID 0) would turn the headline check into something meaningless.
if [ -z "$MAINPID" ] || [ "$MAINPID" -eq 0 ]; then
    echo "    FAIL linnea has no MainPID -- it is not running; skipping the signal test"
    fail=1
elif runuser -u linnea -- kill -0 "$MAINPID" 2>/dev/null; then
    echo "    FAIL the linnea account can still signal production (pid $MAINPID)"; fail=1
else
    ok "the linnea account cannot signal production (EPERM) -- this is the fix"
fi
runuser -u linnea -- pkill -x linnea 2>/dev/null || true
sleep 1
if [ "$(systemctl is-active linnea)" = "active" ]; then
    ok "survived a 'pkill -x linnea' run as the linnea account"
else
    echo "    FAIL production did NOT survive pkill"; fail=1
fi

say "result"
if [ "$fail" -eq 0 ]; then
    echo "    migration complete and verified."
else
    echo "    MIGRATION HAS FAILURES above -- see rollback at the foot of this script." >&2
    exit 1
fi

cat <<'NEXT'

    Still to do by hand:
      - old paths are untouched; after a soak, remove them:
          rm -rf /home/linnea/www/linnea /home/linnea/acme \
                 /home/linnea/certs /home/linnea/spill
      - the qdbg trace trigger has moved with the working directory:
          touch /var/lib/linnea/linnea-qdbg      (was /home/linnea/linnea/linnea-qdbg)
      - confirm renewal end to end:  certbot renew --dry-run

    Rollback (old layout is still in place):
      for u in linnea linnea-api linnea-ws; do
          cp -a /etc/systemd/system/$u.service.bak-MIGRATION /etc/systemd/system/$u.service
      done
      cp -a /etc/logrotate.d/linnea.bak-MIGRATION /etc/logrotate.d/linnea
      systemctl daemon-reload
      systemctl restart linnea-api linnea-ws linnea
NEXT
