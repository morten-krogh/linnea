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

# semantic validation (audit-report-3 Finding 2): the port must be in range, the
# host must be reg-name, and a bracket literal must be a real IPv6 address
[ "$(hc 'beta.test:65536')" = 400 ]
check "authority: out-of-range port 65536 rejected (400)" $?
[ "$(hc 'beta.test:99999')" = 400 ]
check "authority: out-of-range port 99999 rejected (400)" $?
[ "$(hc 'beta.test/foo')" = 400 ]
check "authority: non-reg-name char '/' rejected (400)" $?
[ "$(hc 'beta.test?x')" = 400 ]
check "authority: non-reg-name char '?' rejected (400)" $?
[ "$(hc '[deadbeef]')" = 400 ]
check "authority: bracket contents that are not IPv6 rejected (400)" $?
[ "$(hc '[gggg::1]')" = 400 ]
check "authority: malformed IPv6 literal rejected (400)" $?
[ "$(hc '[::1]')" = 200 ]
check "authority: valid IPv6 literal without a port served (200)" $?
[ "$(hc '[::ffff:1.2.3.4]')" = 200 ]
check "authority: valid v4-mapped IPv6 literal served (200)" $?

# report 126: RFC 3986 3.2.2 gives IP-literal two alternatives --
# "[" ( IPv6address / IPvFuture ) "]" -- and only IPv6address was implemented,
# so "[v1.fe80]", a legal uri-host and therefore a legal Host, was 400. It is
# served like any other name we do not host: by the default vhost, exactly as
# "[::1]" above is. That pairing is the point. A build that simply stopped
# validating bracket contents would pass every acceptance line here, so the
# near-misses below and the "[deadbeef]"/"[gggg::1]" lines above are what
# separate the fix from a hole.
[ "$(hc '[v1.fe80]:443')" = 200 ]
check "authority: IPvFuture literal accepted (200)" $?
[ "$(hc '[v1.fe80]')" = 200 ]
check "authority: IPvFuture literal without a port accepted (200)" $?
[ "$(hc "[vF.a:b-c]:65535")" = 200 ]
check "authority: ':' and sub-delims in an IPvFuture value accepted (200)" $?
# ABNF string literals are case-insensitive (RFC 5234 2.3), and 3986 says so
# again in prose. Python's urlsplit gets this wrong and refuses "V"; we do not.
[ "$(hc '[V9.x]')" = 200 ]
check "authority: the IPvFuture version flag is case-insensitive (200)" $?
# ...and the near-misses, each one byte away from the accepted spelling
[ "$(hc '[v.fe80]')" = 400 ]
check "authority: IPvFuture with an empty version rejected (400)" $?
[ "$(hc '[v1.]')" = 400 ]
check "authority: IPvFuture with an empty address value rejected (400)" $?
[ "$(hc '[v1]')" = 400 ]
check "authority: IPvFuture with no '.' rejected (400)" $?
[ "$(hc '[vg.x]')" = 400 ]
check "authority: a non-hex IPvFuture version flag rejected (400)" $?
[ "$(hc '[v1.a/b]')" = 400 ]
check "authority: a non-reg-name byte in an IPvFuture value rejected (400)" $?
# IPvFuture is unreserved / sub-delims / ":" -- there is no pct-encoded
# alternative in it, the way there is in reg-name
[ "$(hc '[v1.a%20b]')" = 400 ]
check "authority: '%' in an IPvFuture value rejected (400)" $?
# the port rules are the literal's, not a second set: still judged after the ']'
[ "$(hc '[v1.fe80]:65536')" = 400 ]
check "authority: an out-of-range port after an IPvFuture rejected (400)" $?
[ "$(hc '[v1.fe80]x')" = 400 ]
check "authority: junk after an IPvFuture literal rejected (400)" $?

# report 127: reg-name has THREE alternatives and only two were implemented --
#   reg-name = *( unreserved / pct-encoded / sub-delims )   RFC 3986 3.2.2
# -- so "alpha%2Etest", a legal uri-host and therefore a legal Host, was 400,
# indistinguishable from the malformed "alpha%ZZ.test" below. Two independent
# parsers were asked before this changed: nginx 1.30.4 answers every line in
# this block 200, and curl 8.x's URL parser calls "%2E"/"%41" well formed and
# "%ZZ", "%2" and a trailing "%" malformed (exit 3). We take the strict half
# from curl and the acceptance from both.
[ "$(hc 'alpha%2Etest')" = 200 ]
check "authority: a pct-encoded reg-name is accepted (200)" $?
[ "$(hc 'alpha%41.test')" = 200 ]
check "authority: a pct-encoded letter in a reg-name is accepted (200)" $?
[ "$(hc 'alpha%2Etest:8080')" = 200 ]
check "authority: a pct-encoded reg-name with a port is accepted (200)" $?
# lower-case hex is the same octet: HEXDIG comes from ABNF, whose string
# literals are case-insensitive (RFC 5234 2.3)
[ "$(hc 'alpha%2etest')" = 200 ]
check "authority: lower-case pct-encoding hex is accepted (200)" $?
# NOT decoded, and that is the point of this line rather than an omission.
# "beta%2Etest" is not normalized to "beta.test": it matches no configured
# hostname and falls to the default vhost (alpha's root), which is the same
# answer nginx gives it and the same answer "[::1]" and "[v1.fe80]" get above.
# A build that decoded before vhost selection would serve beta's "sub index"
# here and pass every other line in this block.
case "$(hb 'beta%2Etest')" in *"sub index"*) false ;; *doctype*) true ;; *) false ;; esac
check "authority: a pct-encoded name is not decoded for vhost selection" $?
# ...and the near-misses. pct-encoded is exactly "%" HEXDIG HEXDIG (RFC 3986
# 2.1): both digits must be present and both must be hex, or the escape is
# malformed and the authority with it. A build that simply added "%" to the
# reg-name byte table would pass the four acceptance lines above and fail every
# line below -- which is what separates the fix from a hole.
[ "$(hc 'alpha%ZZ.test')" = 400 ]
check "authority: non-hex pct-encoding rejected (400)" $?
[ "$(hc 'alpha%2.test')" = 400 ]
check "authority: one hex digit then a non-hex byte rejected (400)" $?
[ "$(hc 'alpha%2')" = 400 ]
check "authority: a pct-escape truncated to one digit rejected (400)" $?
[ "$(hc 'alpha%')" = 400 ]
check "authority: a bare '%' ending the authority rejected (400)" $?
[ "$(hc '%')" = 400 ]
check "authority: an authority that is only '%' rejected (400)" $?
# the escape may not run into the port either: ':' is not a hex digit, and the
# scan must not treat "reached a delimiter" as "escape complete"
[ "$(hc 'alpha%2:8080')" = 400 ]
check "authority: a pct-escape cut short by ':port' rejected (400)" $?
# the rest of the grammar is unchanged by pct-encoding: the port is still
# judged, and a pct-encoded name does not buy an unjudged one
[ "$(hc 'alpha%2Etest:99999')" = 400 ]
check "authority: an out-of-range port after a pct-encoded name rejected (400)" $?

kill $auth_pid 2>/dev/null
wait $auth_pid 2>/dev/null
