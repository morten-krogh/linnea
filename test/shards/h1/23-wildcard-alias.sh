# Finding 1 (audit-report-2): listener identity is the canonical endpoint, not
# the host TEXT. "::" and "0.0.0.0" both bind in6addr_any, so two servers that
# spell the wildcard differently on one port are ONE SO_REUSEPORT listener with
# one vhost table -- not two listeners that split a hostname between them. Before
# the fix, a request for the second hostname landed on whichever of the two
# listeners the kernel's reuseport hash chose, and the one that did not own that
# vhost fell through to its default root (the audit measured a 15/25 split).
# Repro: alpha.test on "::", beta.test on "0.0.0.0", disjoint roots; every
# beta.test request must reach beta's own root.
start_server $CFG/wildcard-alias.json
wa_pid=$SRV_PID
miss=0
for _ in $(seq 1 30); do
    b=$(curl -s --max-time 3 -H "Host: beta.test" http://127.0.0.1:${P61465}/ 2>/dev/null)
    case "$b" in *"sub index"*) ;; *) miss=$((miss+1)) ;; esac
done
[ "$miss" -eq 0 ]
check "wildcard alias: beta.test on 0.0.0.0 always served from its own root (misses=$miss/30)" $?
# alpha.test, on the ::-spelled wildcard, is served from that SAME shared listener
a=$(curl -s --max-time 3 -H "Host: alpha.test" http://127.0.0.1:${P61465}/ 2>/dev/null)
case "$a" in *doctype*) true ;; *) false ;; esac
check "wildcard alias: alpha.test on :: served from the same shared listener" $?
kill $wa_pid 2>/dev/null
wait $wa_pid 2>/dev/null
