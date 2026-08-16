# Stop the shared h1 fixtures and release port 61100 so a following tls
# shard (in a serial run sharing this port base) can rebind it.
# (was the unconditional teardown between region 1's two parts, 3096-3105.)

kill $server_pid $backend_pid $ws_direct_pid $ws_proxy_pid 2>/dev/null
# the next block binds 61100 again, so let this one's listener go first
for _ in $(seq 1 60); do
    (echo > /dev/tcp/127.0.0.1/${P61100}) >/dev/null 2>&1 || break
    sleep 0.1
done
wait $server_pid 2>/dev/null
wait $backend_pid 2>/dev/null
wait $ws_direct_pid $ws_proxy_pid 2>/dev/null
rm -f "$LOG" $WWW/big.txt $WWW/upload.bin $WWW/upload2.bin $WWW/h2range.bin $WWW/huge.bin $WWW/enc.txt $WWW/enc.txt.gz $WWW/enc.txt.br
