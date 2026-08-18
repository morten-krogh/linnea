# Finding 2 (audit-report-2): authority parsing must validate the port grammar
# and handle bracketed IPv6, instead of splitting at the first ':' and looking
# no further. Two vhosts share one listener (alpha.test -> www, beta.test ->
# www/sub); a malformed authority is a 400, a valid one still routes.
start_server $CFG/authority-vhosts.json
auth_pid=$SRV_PID
hc() { curl -s -o /dev/null -w '%{http_code}' --max-time 3 -H "Host: $1" http://127.0.0.1:${P61466}/; }
hb() { curl -s --max-time 3 -H "Host: $1" http://127.0.0.1:${P61466}/; }

# valid authorities still route by hostname, with or without a numeric port
case "$(hb beta.test)"       in *"sub index"*) true ;; *) false ;; esac
check "authority: beta.test routes to its vhost" $?
case "$(hb beta.test:8080)"  in *"sub index"*) true ;; *) false ;; esac
check "authority: a valid numeric port is stripped, vhost still matches" $?
case "$(hb alpha.test)"      in *doctype*) true ;; *) false ;; esac
check "authority: alpha.test routes to its vhost" $?

# malformed authorities are 400, not served (were 200 before the parser)
[ "$(hc 'beta.test:garbage')" = 400 ]
check "authority: non-numeric port rejected (400)" $?
[ "$(hc 'beta.test:80:bad')" = 400 ]
check "authority: extra port component rejected (400)" $?
[ "$(hc '[::1')" = 400 ]
check "authority: unterminated IPv6 bracket rejected (400)" $?
[ "$(hc '[::1]x')" = 400 ]
check "authority: junk after IPv6 literal rejected (400)" $?

# a well-formed bracketed IPv6 literal we do not host is served by the default
# vhost -- parsed as ::1, not mangled to "["
[ "$(hc '[::1]:443')" = 200 ]
check "authority: valid bracketed IPv6 literal served by default (200)" $?

kill $auth_pid 2>/dev/null
wait $auth_pid 2>/dev/null
