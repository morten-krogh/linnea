# Specific-IPv6 and v6-only host binding. A "::1" host binds the IPv6 loopback
# only; a "::" host with v6only=1 binds all IPv6 but excludes IPv4. Both must
# serve over ::1 and refuse a connection to 127.0.0.1 -- the family isolation the
# IPv6-literal parser and the IPV6_V6ONLY socket option together provide. (The
# dual-stack default "::" is covered by the h3 dual-stack test.)
start_server $CFG/v6-bind.json
v6_pid=$SRV_PID

# host "::1": serves over ::1, and 127.0.0.1 has nothing bound (refused)
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "http://[::1]:${P61469}/hello.txt")
[ "$code" = 200 ]
check "ipv6: host \"::1\" serves over ::1 ($code)" $?
curl -s -o /dev/null --max-time 4 "http://127.0.0.1:${P61469}/hello.txt"
[ $? -ne 0 ]
check "ipv6: host \"::1\" refuses IPv4 (127.0.0.1)" $?

# host "::" with v6only=1: serves over ::1, refuses IPv4
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "http://[::1]:${P61470}/hello.txt")
[ "$code" = 200 ]
check "ipv6: host \"::\" v6only serves over ::1 ($code)" $?
curl -s -o /dev/null --max-time 4 "http://127.0.0.1:${P61470}/hello.txt"
[ $? -ne 0 ]
check "ipv6: host \"::\" v6only refuses IPv4 (127.0.0.1)" $?

kill $v6_pid 2>/dev/null
wait $v6_pid 2>/dev/null
