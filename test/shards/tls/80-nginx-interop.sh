# proxy_h2 against a REAL HTTP/2 server. Every other backend check in this suite
# talks to linnea or to a Python fixture, both of which we wrote -- so both agree
# with us about anything we got wrong. nginx does not: it was nginx that showed
# the backend leg refusing an 18188-byte header block it had every right to send,
# and nginx that showed the leg writing a synthesized head past the end of the
# buffer it goes in. Skipped, not failed, where nginx is absent.
if command -v nginx >/dev/null 2>&1 \
   && grep -qw tls /proc/sys/net/ipv4/tcp_available_ulp 2>/dev/null \
   && command -v openssl >/dev/null 2>&1; then
    ngx=$RUNDIR/nginx; mkdir -p $ngx/logs $ngx/www $ngx/tmp
    printf 'NGINX-OK\n' > $ngx/www/small.txt
    python3 -c "open('$ngx/www/big.bin','w').write('B'*200000)"
    PIN=$(openssl x509 -in test/tls/server.crt -noout -pubkey \
          | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary \
          | xxd -p -c256)
    # 24 headers x ~1000 bytes: past one frame, so nginx must split the block
    # across HEADERS + CONTINUATION, and past every head buffer we relay into.
    python3 - "$PWD/$ngx" "$PWD" "${P61726}" <<'PY'
import sys
d, repo, port = sys.argv[1], sys.argv[2], sys.argv[3]
big = "\n".join('            add_header X-Big-%02d "%s" always;' % (i, chr(97+i%26)*1000)
                for i in range(24))
open(d + "/nginx.conf", "w").write(f'''worker_processes 1;
daemon off;
error_log {d}/logs/error.log crit;
pid {d}/logs/nginx.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_body_temp_path {d}/tmp/body;
    proxy_temp_path {d}/tmp/proxy;
    fastcgi_temp_path {d}/tmp/fcgi;
    uwsgi_temp_path {d}/tmp/uwsgi;
    scgi_temp_path {d}/tmp/scgi;
    default_type text/plain;
    server {{
        listen 127.0.0.1:{port} ssl;
        http2 on;
        server_name localhost;
        ssl_certificate     {repo}/test/tls/server.crt;
        ssl_certificate_key {repo}/test/tls/server.key;
        ssl_protocols TLSv1.3;
        ssl_ecdh_curve X25519;
        root {d}/www;
        location = /hello  {{ return 200 "NGINX-HELLO\\n"; }}
        location = /gone   {{ return 301 "https://example.com/new"; }}
        location = /bighdr {{
{big}
            return 200 "BIGHDR-OK\\n";
        }}
    }}
}}
''')
PY
    cat > $CFG/ngx-fe.json <<EOF
{ "log": "$PWD/$RUNDIR/ngx-fe.log", "workers": 1,
  "servers": [ { "host": "127.0.0.1", "port": ${P61727}, "hostname": "localhost",
    "cert": "$PWD/test/tls/server.crt", "key": "$PWD/test/tls/server.key",
    "locations": [ { "prefix": "/", "proxy": "127.0.0.1:${P61726}",
      "proxy_tls": 1, "proxy_pin": "$PIN", "proxy_sni": "localhost",
      "proxy_h2": 1 } ] } ] }
EOF
    nginx -p $PWD/$ngx -e $PWD/$ngx/logs/error.log -c $PWD/$ngx/nginx.conf >/dev/null 2>&1 &
    ngxpid=$!
    start_server $CFG/ngx-fe.json
    sleep 0.7
    NCA="--cacert $PWD/test/tls/server.crt --resolve localhost:${P61727}:127.0.0.1"

    for proto in --http1.1 --http2; do
        [ "$(curl -s $proto $NCA --max-time 10 https://localhost:${P61727}/hello)" = "NGINX-HELLO" ]
        check "nginx interop: a real h2 backend relays its body ($proto client)" $?
        [ "$(curl -s $proto $NCA --max-time 15 https://localhost:${P61727}/big.bin | wc -c)" = 200000 ]
        check "nginx interop: a 200000-byte body relays intact ($proto client)" $?
        [ "$(curl -s -o /dev/null -w '%{http_code}' $proto $NCA --max-time 10 \
             https://localhost:${P61727}/gone)" = 301 ]
        check "nginx interop: a 301 relays with its status ($proto client)" $?
    done
    [ "$(curl -s -o /dev/null -w '%{http_code}' -I --http1.1 $NCA --max-time 10 \
         https://localhost:${P61727}/small.txt)" = 200 ]
    check "nginx interop: HEAD" $?

    # A header block past one frame AND past every head buffer we relay into.
    # 502 is the documented answer (docs/config.md, "Response head limits") --
    # what must not happen is a relayed-but-truncated head, and what must not be
    # said is that nginx failed to answer. It answered in full.
    : > $RUNDIR/ngx-fe.log
    code=$(curl -s -o /dev/null -w '%{http_code}' --http1.1 $NCA --max-time 10 \
           https://localhost:${P61727}/bighdr)
    [ "$code" = 502 ]
    check "nginx interop: a head past our limit is refused, not truncated ($code)" $?
    sleep 0.2
    awk '/past our limit/{n++} END{exit !(n>0)}' $RUNDIR/ngx-fe.log
    check "nginx interop: ...and the log says it was ours, not the backend's" $?
    awk '/did not answer/{n++} END{exit (n>0)}' $RUNDIR/ngx-fe.log
    check "nginx interop: ...and does not blame the backend for silence" $?

    : > $RUNDIR/ngx_conc.txt
    cpids=""
    for i in $(seq 20); do
        curl -s -o /dev/null --http2 $NCA --max-time 15 -w '%{http_code}\n' \
            https://localhost:${P61727}/small.txt >>$RUNDIR/ngx_conc.txt &
        cpids="$cpids $!"
    done
    wait $cpids 2>/dev/null
    [ "$(grep -c '^200' $RUNDIR/ngx_conc.txt)" = 20 ]
    check "nginx interop: 20 concurrent h2 clients through one front" $?

    if [ -x "$CURLH3" ]; then
        [ "$("$CURLH3" --http3-only -sk --max-time 10 \
             --resolve localhost:${P61727}:127.0.0.1 \
             https://localhost:${P61727}/hello)" = "NGINX-HELLO" ]
        check "nginx interop: an h3 client is served from a real h2 backend" $?
    else
        check "nginx interop: h3 client (skipped: curl-h3 unavailable)" 0
    fi
    kill $ngxpid 2>/dev/null; wait $ngxpid 2>/dev/null
    rm -f $RUNDIR/ngx_conc.txt
else
    check "nginx interop (skipped: nginx, openssl or the tls ULP unavailable)" 0
fi
