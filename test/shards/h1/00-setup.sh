# Shard: HTTP/1, proxying, websockets, uploads. This file starts the shared
# fixtures the h1 checks use: the proxy backend (61100), two websocket
# backends, and the main listen.json server. (was run_tests.sh gap 1580-1640.)

rm -f "$LOG"
# A file spanning several pages: every other fixture fits in one, which is
# exactly what let a wrong mmap length go unnoticed.
python3 -c "open('$WWW/big.txt','w').write('B'*100000)"
# Pre-compressed variants. Each one holds different text, so a test can
# tell which file was served; real deployments would compress the same
# bytes. The .gz is real gzip (curl --compressed decodes it); the .br is
# not real brotli, which linnea neither produces nor inspects.
python3 - "$WWW" <<'PY'
import gzip, sys
W = sys.argv[1]                      # the run's own document root
open(W + '/enc.txt', 'w').write('plain payload')
with gzip.open(W + '/enc.txt.gz', 'wb') as f:
    f.write(b'gzip payload')
open(W + '/enc.txt.br', 'wb').write(b'br payload')
PY

SEEN=$RUNDIR/linnea_backend_seen.log       # what actually reached a backend
rm -f "$SEEN"
python3 test/proxy_backend.py >/dev/null 2>&1 &
backend_pid=$!
backend_ready
# The websocket backend, twice: 61701 is spoken to directly, 61702 sits behind
# linnea's /ws location. Two instances rather than one, so the counter each
# battery sees is its own and the two runs cannot perturb each other.
./bin/linnea-ws ${P61701} >/dev/null 2>&1 &
ws_direct_pid=$!
./bin/linnea-ws ${P61702} >/dev/null 2>&1 &
ws_proxy_pid=$!
for _ in $(seq 1 60); do
    (echo > /dev/tcp/127.0.0.1/${P61701}) >/dev/null 2>&1 && \
    (echo > /dev/tcp/127.0.0.1/${P61702}) >/dev/null 2>&1 && break
    sleep 0.1
done
start_server $CFG/listen.json
server_pid=$SRV_PID
sleep 0.3
