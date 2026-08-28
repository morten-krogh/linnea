# SNI and connection coalescing over TLS/h3: misdirected-request 421 across
# certificates, and an independent HTTP/3 client where one is available.



    # --- SNI: two TLS vhosts share 127.0.0.1:61444, each with its own cert
    start_server $CFG/tls-sni.json
    sni_server_pid=$SRV_PID
    sleep 0.3
    subj=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:${P61444} \
        -servername sni.test 2>/dev/null | openssl x509 -noout -subject)
    echo "$subj" | grep -q "CN=sni.test"
    check "sni selects the named vhost cert" $?
    subj=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:${P61444} \
        -servername localhost 2>/dev/null | openssl x509 -noout -subject)
    echo "$subj" | grep -q "CN=localhost"
    check "sni selects the owner cert by name" $?
    subj=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:${P61444} \
        -noservername 2>/dev/null | openssl x509 -noout -subject)
    echo "$subj" | grep -q "CN=localhost"
    check "no sni falls back to the listener owner" $?
    subj=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:${P61444} \
        -servername unknown.test 2>/dev/null | openssl x509 -noout -subject)
    echo "$subj" | grep -q "CN=localhost"
    check "unknown sni falls back to the listener owner" $?
    # the SAME must hold over HTTP/3: the QUIC listener on this port registers both
    # vhosts, and the ClientHello SNI selects the certificate (before this, h3 always
    # served the first vhost's cert, so a second name got the wrong one).
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        python3 test/quic/h3_sni_cert_test.py ${P61444} sni.test sni.test >/dev/null 2>&1
        check "h3 sni selects the named vhost cert" $?
        python3 test/quic/h3_sni_cert_test.py ${P61444} localhost localhost >/dev/null 2>&1
        check "h3 sni selects the owner cert by name" $?
    fi
    # every h3 vhost advertises Alt-Svc, not only the socket owner, so each origin
    # tells its own clients they can switch to h3 (a non-owner vhost is checked).
    curl -s -D - -o /dev/null --http2 --cacert test/tls/sni.crt \
        --resolve sni.test:${P61444}:127.0.0.1 https://sni.test:${P61444}/page.html \
        | grep -qi 'alt-svc: h3='
    check "h3 alt-svc advertised by a non-owner vhost" $?
    # h2 is on by default (tls-sni.json sets no "http2" key): a static vhost
    # negotiates h2.
    echo | timeout 5 openssl s_client -connect 127.0.0.1:${P61444} -CAfile test/tls/sni.crt \
        -servername sni.test -tls1_3 -alpn h2,http/1.1 2>/dev/null \
        | grep -q "ALPN protocol: h2"
    check "alpn: h2 on by default (static vhost)" $?
    # a full request via the SNI vhost: curl verifies against the sni.test
    # cert AND the Host routing must land on the sni.test docroot (which
    # holds page.html; the listener owner does not). h2 is on by default now,
    # so this also exercises SNI vhost routing over HTTP/2.
    resp=$(curl -s --max-time 5 --cacert test/tls/sni.crt \
        --resolve sni.test:${P61444}:127.0.0.1 https://sni.test:${P61444}/page.html)
    check_http "sni end to end (cert + vhost routing)" "subdirectory page" "$resp"

    # Q126: h2 answers only for names the certificate it presented covers —
    # the rule h3 got in Q124. A cross-certificate request gets 421, a name
    # we do not host is served by the connection's own vhost, and two vhosts
    # sharing ONE certificate still coalesce onto a single connection. The
    # worker-PID check is not ceremony: the first version of this crashed the
    # worker (the 421 path skipped the vhost the response builder reads), and
    # a crash looks exactly like a closed connection from the client side.
    start_server $CFG/tls-coalesce.json
    coal_h2_pid=$SRV_PID
    sleep 0.4
    md_before=$(workers_of $sni_server_pid)
    timeout 60 python3 test/tls/h2_misdirected.py $CA ${P61444} ${P61459} >/dev/null 2>&1
    md_rc=$?
    md_after=$(workers_of $sni_server_pid)
    [ "$md_rc" -eq 0 ] && [ -n "$md_before" ] && [ "$md_before" = "$md_after" ]
    check "http2 misdirected request: 421 across certs, coalescing kept" $?
    kill $coal_h2_pid 2>/dev/null
    wait $coal_h2_pid 2>/dev/null

    # Q124: h3 honours :authority instead of serving whatever the TLS SNI
    # chose, and answers a name this connection's certificate does not cover
    # with 421 rather than the other vhost's page.
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        # 150, not 90. Every malformed authority in that file waits out a full
        # five-second read for a response its reset stream will never send, so
        # the runtime is set by how many rejections it checks. Measured: the
        # report-126 set was ~83s against a 90s budget -- an 8% margin -- and
        # report 127's two added rejections take it to 93s, so the check failed
        # on the timeout rather than on the server. (Six added rejections, the
        # set h1 and h2 carry, measured 113s; that is why h3 carries two.)
        timeout 150 python3 test/quic/h3_authority_test.py ${P61444} >/dev/null 2>&1
        check "h3 authority selects the vhost; cross-cert gets 421" $?
    else
        check "h3 authority test (skipped: deps unavailable)" 0
    fi

    # ...and the other side of that strictness: two vhosts sharing ONE
    # certificate are both names the connection can speak for, so a single
    # h3 connection serves both (what a browser coalesces). Own server: the
    # two vhosts differ from the SNI pair in using the same cert.
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        start_server $CFG/tls-coalesce.json
        coal_pid=$SRV_PID
        sleep 0.4
        timeout 60 python3 test/quic/h3_coalesce_test.py ${P61459} >/dev/null 2>&1
        check "h3 coalescing: one cert, two vhosts, one connection" $?
        kill $coal_pid 2>/dev/null
        wait $coal_pid 2>/dev/null
    else
        check "h3 coalescing test (skipped: deps unavailable)" 0
    fi
    kill $sni_server_pid 2>/dev/null
    wait $sni_server_pid 2>/dev/null
    rm -f "$LOG"
