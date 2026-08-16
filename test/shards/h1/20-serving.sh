# HTTP/1 serving, routing, caching, ranges, vhosts, proxying, uploads,
# websockets, spill, termination logs. (was region 1 part one, 1699-3094.)


# check_http <name> <grep-pattern> <response-text>

# raw_http <request> — send bytes, print the full response.
# The request carries literal \r\n escapes; raw_http.py expands them.

# --- log file ---
grep -q "listening on 127.0.0.1:${P61080} (one.test)" "$LOG"
check "log listening line" $?
n=$(grep -c "listening on 127.0.0.1:${P61080}" "$LOG")
[ "$n" -eq 1 ]
check "shared listener bound once" $?

# --- bind conflict against the running server ---
run_test "address in use"  1 stderr "cannot bind to 127.0.0.1:${P61080} (errno 98)" \
    $BIN --config $CFG/dup-bind.json

# --- static file serving ---
resp=$(curl -s --max-time 2 http://127.0.0.1:${P61080}/hello.txt)
check_http "file txt body"     "hello from linnea" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/hello.txt)
check_http "file txt mime"     "Content-Type: text/plain" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/)
check_http "index html body"   "linnea index page" "$resp"
check_http "index html mime"   "Content-Type: text/html" "$resp"

# --- redirect location: 301 with the raw request target appended ---
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61090}/old)
check_http "redirect status"   "301 Moved Permanently" "$resp"
check_http "redirect location" "Location: https://example.com/old" "$resp"
check_http "redirect no body"  "Content-Length: 0" "$resp"
resp=$(curl -si --max-time 2 "http://127.0.0.1:${P61090}/old/a%20b?x=1&y=2")
check_http "redirect keeps raw path+query" "Location: https://example.com/old/a%20b?x=1&y=2" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/style.css)
check_http "css mime"          "Content-Type: text/css" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/favicon.ico)
check_http "ico mime"          "Content-Type: image/x-icon" "$resp"
resp=$(curl -s --max-time 2 http://127.0.0.1:${P61090}/sub/page.html)
check_http "subdirectory file" "subdirectory page" "$resp"

# --- location routing: 61090 has "/" -> test/www/sub and "/sub" -> test/www ---
resp=$(curl -s --max-time 2 http://127.0.0.1:${P61090}/page.html)
check_http "location root match"  "subdirectory page" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61090}/hello.txt)
check_http "location root scopes" "404 Not Found" "$resp"
# /sub/page.html matches the longer "/sub" prefix (root test/www), not "/"
resp=$(curl -s --max-time 2 http://127.0.0.1:${P61090}/sub/page.html)
check_http "longest prefix wins"  "subdirectory page" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/no-such-file)
check_http "http 404"          "404 Not Found" "$resp"
resp=$(curl -si --max-time 2 -I http://127.0.0.1:${P61080}/hello.txt)
check_http "HEAD length"       "Content-Length: 18" "$resp"
resp=$(curl -si --max-time 2 -X POST http://127.0.0.1:${P61080}/hello.txt)
check_http "http 405"          "405 Method Not Allowed" "$resp"

# a file larger than one page: the mapped length must be the whole file
n=$(curl -s --max-time 5 http://127.0.0.1:${P61080}/big.txt | wc -c)
[ "$n" -eq 100000 ]
check "large file length ($n bytes)" $?
junk=$(curl -s --max-time 5 http://127.0.0.1:${P61080}/big.txt | tr -d 'B' | wc -c)
[ "$junk" -eq 0 ]
check "large file intact" $?

# --- caching: ETag / Last-Modified and conditional requests ---
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/hello.txt)
check_http "etag present"        "ETag: \"" "$resp"
check_http "last-modified present" "Last-Modified: " "$resp"
printf '%s' "$resp" | grep -qE '^ETag: "[0-9a-f]+-12"'
check "etag is mtime-size in hex" $?
printf '%s' "$resp" | grep -qE '^Last-Modified: [A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT'
check "last-modified is an HTTP date" $?
check_http "server header"       "Server: linnea" "$resp"
printf '%s' "$resp" | grep -qE '^Date: [A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT'
check "date is an HTTP date" $?
check_http "cache-control from config" "Cache-Control: max-age=60" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/no-such-file)
check_http "404 server header"   "Server: linnea" "$resp"

resp=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/hello.txt)
etag=$(printf '%s' "$resp" | grep -i '^etag:' | tr -d '\r' | cut -d' ' -f2)
lastmod=$(printf '%s' "$resp" | grep -i '^last-modified:' | tr -d '\r' | cut -d' ' -f2-)

resp=$(curl -si --max-time 2 -H "If-None-Match: $etag" http://127.0.0.1:${P61080}/hello.txt)
check_http "if-none-match 304"   "304 Not Modified" "$resp"
check_http "304 repeats etag"    "ETag: $etag" "$resp"
check_http "304 keeps alive"     "Connection: keep-alive" "$resp"
check_http "304 server header"   "Server: linnea" "$resp"
check_http "304 date header"     "Date: " "$resp"
check_http "304 repeats cache-control" "Cache-Control: max-age=60" "$resp"
printf '%s' "$resp" | grep -qF "hello from linnea"
[ $? -ne 0 ]
check "304 carries no body" $?
# a 304 that cost a new connection each time would defeat revalidation
before=$(grep -c "accepted connection" "$LOG")
curl -s --max-time 4 -H "If-None-Match: $etag" -o /dev/null \
    http://127.0.0.1:${P61080}/hello.txt http://127.0.0.1:${P61080}/hello.txt
after=$(grep -c "accepted connection" "$LOG")
[ $((after - before)) -eq 1 ]
check "304 single accept" $?

resp=$(curl -si --max-time 2 -H 'If-None-Match: "stale"' http://127.0.0.1:${P61080}/hello.txt)
check_http "stale etag 200"      "hello from linnea" "$resp"
resp=$(curl -si --max-time 2 -H "If-None-Match: W/$etag" http://127.0.0.1:${P61080}/hello.txt)
check_http "weak etag 304"       "304 Not Modified" "$resp"
resp=$(curl -si --max-time 2 -H 'If-None-Match: *' http://127.0.0.1:${P61080}/hello.txt)
check_http "if-none-match star"  "304 Not Modified" "$resp"
resp=$(curl -si --max-time 2 -H "If-None-Match: \"a\", W/\"b\", $etag" http://127.0.0.1:${P61080}/hello.txt)
check_http "etag list 304"       "304 Not Modified" "$resp"
resp=$(curl -si --max-time 2 -I -H "If-None-Match: $etag" http://127.0.0.1:${P61080}/hello.txt)
check_http "HEAD 304"            "304 Not Modified" "$resp"

resp=$(curl -si --max-time 2 -H "If-Modified-Since: $lastmod" http://127.0.0.1:${P61080}/hello.txt)
check_http "if-modified-since 304" "304 Not Modified" "$resp"
resp=$(curl -si --max-time 2 -z "$lastmod" http://127.0.0.1:${P61080}/hello.txt)
check_http "curl time-cond 304"  "304 Not Modified" "$resp"
resp=$(curl -si --max-time 2 -H "If-Modified-Since: Wed, 01 Jan 2020 00:00:00 GMT" http://127.0.0.1:${P61080}/hello.txt)
check_http "older date 200"      "hello from linnea" "$resp"
# an unparseable date must be ignored, not treated as a condition
resp=$(curl -si --max-time 2 -H "If-Modified-Since: not a date" http://127.0.0.1:${P61080}/hello.txt)
check_http "bad date ignored"    "hello from linnea" "$resp"
# An rfc850 date now PARSES (RFC 9110 5.6.7); 1994 is simply older than the
# file, so the body is still what comes back. The name said "ignored" when the
# format was rejected outright — the outcome is the same, the reason is not.
resp=$(curl -si --max-time 2 -H "If-Modified-Since: Sunday, 06-Nov-94 08:49:37 GMT" http://127.0.0.1:${P61080}/hello.txt)
check_http "rfc850 date parses, and 1994 is older" "hello from linnea" "$resp"
# If-None-Match wins outright when both are present
resp=$(curl -si --max-time 2 -H 'If-None-Match: "x"' -H "If-Modified-Since: $lastmod" http://127.0.0.1:${P61080}/hello.txt)
check_http "if-none-match wins"  "hello from linnea" "$resp"

grep -qF '"GET /hello.txt HTTP/1.1" 304 0' "$LOG"
check "request log 304" $?

# --- pre-compressed variants: enc.txt has both a .br and a .gz beside it ---
# enc_of <accept-encoding> — the Content-Encoding linnea picked, if any.
# grep -a: the gzip variant's body is binary.
[ "$(enc_of 'gzip, br')" = "br" ]
check "br preferred over gzip" $?
[ "$(body_of 'gzip, br')" = "br payload" ]
check "br variant served" $?
[ "$(enc_of 'gzip')" = "gzip" ]
check "gzip when br unwanted" $?
[ "$(enc_of 'deflate, br')" = "br" ]
check "unknown codings skipped" $?
[ "$(enc_of 'BR')" = "br" ]
check "accept-encoding is case-insensitive" $?
[ -z "$(enc_of 'identity')" ]
check "identity gets the plain file" $?
[ "$(body_of 'identity')" = "plain payload" ]
check "plain body when no coding taken" $?
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/enc.txt)
printf '%s' "$resp" | grep -qai '^content-encoding'
[ $? -ne 0 ]
check "no accept-encoding, no coding" $?
check_http "plain body without accept-encoding" "plain payload" "$resp"
# q=0 is a refusal, and the fallback must still find the other variant
[ -z "$(enc_of 'br;q=0')" ]
check "q=0 refuses a coding" $?
[ "$(enc_of 'br;q=0, gzip')" = "gzip" ]
check "q=0 falls back to gzip" $?
[ "$(enc_of 'br;q=0.001')" = "br" ]
check "a small q still accepts" $?
[ -z "$(enc_of 'br;q=0.000')" ]
check "q=0.000 refuses too" $?
# h1-14: RFC 9110 5.3 makes repeated field lines equivalent to the comma-joined
# value, so a client may split its codings over several Accept-Encoding lines.
# Taking only the first dropped every coding after it — "identity" then "br"
# served the plain file. Each line is now its own span and a coding is taken if
# any of them accepts it, which is the answer joining them would have given.
enc_of2() {
    curl -si --max-time 2 -H "Accept-Encoding: $1" -H "Accept-Encoding: $2" \
        http://127.0.0.1:${P61080}/enc.txt \
        | grep -ai '^content-encoding' | tr -d '\r' | sed 's/.*: //'
}
[ "$(enc_of2 'identity' 'br')" = "br" ]
check "split accept-encoding: the second line is honoured" $?
[ "$(enc_of2 'identity' 'gzip')" = "gzip" ]
check "split accept-encoding: gzip on the second line" $?
[ "$(enc_of2 'gzip' 'br')" = "br" ]
check "split accept-encoding: br still preferred over gzip" $?
# the type comes from the name before the suffix, not from ".br"
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: br' http://127.0.0.1:${P61080}/enc.txt)
check_http "type ignores the suffix" "Content-Type: text/plain" "$resp"
check_http "variant length"          "Content-Length: 10" "$resp"
check_http "variant vary"            "Vary: Accept-Encoding" "$resp"
# h1-15: a variant with no plain file beside it is served to whoever takes the
# encoding and 404s everyone else, so the miss is content-negotiated too. If
# that 404 omits Vary, a shared cache stores it under the bare URL and then
# hands it to the very clients the variant was for — the 200 becomes
# unreachable through the cache. Both answers must agree on Vary.
printf 'br only payload' > $WWW/varonly.txt.br
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: br' http://127.0.0.1:${P61080}/varonly.txt)
check_http "variant-only file served to a br client" "HTTP/1.1 200" "$resp"
check_http "variant-only 200 varies"                 "Vary: Accept-Encoding" "$resp"
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: identity' http://127.0.0.1:${P61080}/varonly.txt)
check_http "variant-only 404s a client that cannot take it" "HTTP/1.1 404" "$resp"
check_http "that 404 varies too (h1-15)"                    "Vary: Accept-Encoding" "$resp"
rm -f $WWW/varonly.txt.br
# curl decoding the real gzip end to end
[ "$(curl -s --max-time 2 --compressed -H 'Accept-Encoding: gzip' http://127.0.0.1:${P61080}/enc.txt)" = "gzip payload" ]
check "gzip variant decodes" $?
# a file with no variants must not claim an encoding, but still varies
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: gzip, br' http://127.0.0.1:${P61080}/hello.txt)
printf '%s' "$resp" | grep -qai '^content-encoding'
[ $? -ne 0 ]
check "no variant, no coding" $?
check_http "no variant still varies" "Vary: Accept-Encoding" "$resp"
check_http "no variant serves plain" "hello from linnea" "$resp"

# Each variant is its own representation: a cache must never hand one to a
# client that asked for another, so the validators have to differ.
etag_br=$(curl -si --max-time 2 -H 'Accept-Encoding: br' http://127.0.0.1:${P61080}/enc.txt | grep -ai '^etag:' | tr -d '\r' | cut -d' ' -f2)
etag_gz=$(curl -si --max-time 2 -H 'Accept-Encoding: gzip' http://127.0.0.1:${P61080}/enc.txt | grep -ai '^etag:' | tr -d '\r' | cut -d' ' -f2)
etag_pl=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/enc.txt | grep -ai '^etag:' | tr -d '\r' | cut -d' ' -f2)
[ -n "$etag_br" ] && [ "$etag_br" != "$etag_gz" ] && [ "$etag_gz" != "$etag_pl" ] && [ "$etag_br" != "$etag_pl" ]
check "each variant has its own etag" $?
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: br' -H "If-None-Match: $etag_br" http://127.0.0.1:${P61080}/enc.txt)
check_http "variant revalidates 304" "304 Not Modified" "$resp"
check_http "variant 304 varies"      "Vary: Accept-Encoding" "$resp"
printf '%s' "$resp" | grep -qai '^content-encoding'
[ $? -ne 0 ]
check "variant 304 omits the coding" $?
# the br etag says nothing about the gzip or plain representations
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: gzip' -H "If-None-Match: $etag_br" http://127.0.0.1:${P61080}/enc.txt)
check_http "cross-variant etag 200" "200 OK" "$resp"
resp=$(curl -si --max-time 2 -H "If-None-Match: $etag_br" http://127.0.0.1:${P61080}/enc.txt)
check_http "variant etag vs plain 200" "plain payload" "$resp"

# --- Range requests: hello.txt is the 18 bytes "hello from linnea\n" ---
resp=$(curl -si --max-time 2 -r 0-4 http://127.0.0.1:${P61080}/hello.txt)
check_http "range 206"           "206 Partial Content" "$resp"
check_http "range content-range" "Content-Range: bytes 0-4/18" "$resp"
check_http "range length"        "Content-Length: 5" "$resp"
printf '%s' "$resp" | grep -qF "hello from"
[ $? -ne 0 ]
check "range body is the slice" $?
check_http "range body"          "hello" "$resp"
resp=$(curl -s --max-time 2 -r 6- http://127.0.0.1:${P61080}/hello.txt)
[ "$resp" = "from linnea" ]     # the trailing newline is byte 17
check "range open end" $?
resp=$(curl -s --max-time 2 -r -7 http://127.0.0.1:${P61080}/hello.txt)
[ "$resp" = "linnea" ]
check "range suffix" $?
resp=$(curl -si --max-time 2 -r 0-0 http://127.0.0.1:${P61080}/hello.txt)
check_http "range single byte"   "Content-Range: bytes 0-0/18" "$resp"
check_http "range single length" "Content-Length: 1" "$resp"
# a last past the end means "to the end"
resp=$(curl -si --max-time 2 -H 'Range: bytes=6-9999' http://127.0.0.1:${P61080}/hello.txt)
check_http "range clamped last"  "Content-Range: bytes 6-17/18" "$resp"
# a suffix longer than the file is the whole file, still a 206
resp=$(curl -si --max-time 2 -H 'Range: bytes=-9999' http://127.0.0.1:${P61080}/hello.txt)
check_http "range long suffix"   "Content-Range: bytes 0-17/18" "$resp"
# 200s advertise the support
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/hello.txt)
check_http "accept-ranges"       "Accept-Ranges: bytes" "$resp"
# unsatisfiable: starts at or past the end -> 416 naming the length
resp=$(curl -si --max-time 2 -H 'Range: bytes=99-' http://127.0.0.1:${P61080}/hello.txt)
check_http "range 416"           "416 Range Not Satisfiable" "$resp"
check_http "416 content-range"   "Content-Range: bytes */18" "$resp"
check_http "416 keeps alive"     "Connection: keep-alive" "$resp"
resp=$(curl -si --max-time 2 -H 'Range: bytes=-0' http://127.0.0.1:${P61080}/hello.txt)
check_http "range -0 is 416"     "416 Range Not Satisfiable" "$resp"
# not understood -> ignored -> the full 200
resp=$(curl -si --max-time 2 -H 'Range: bytes=5-2' http://127.0.0.1:${P61080}/hello.txt)
check_http "backwards range 200" "200 OK" "$resp"
resp=$(curl -si --max-time 2 -H 'Range: bytes=abc' http://127.0.0.1:${P61080}/hello.txt)
check_http "garbage range 200"   "200 OK" "$resp"
resp=$(curl -si --max-time 2 -H 'Range: potatoes=0-4' http://127.0.0.1:${P61080}/hello.txt)
check_http "other unit 200"      "200 OK" "$resp"
resp=$(curl -si --max-time 2 -H 'Range: bytes=0-1,3-4' http://127.0.0.1:${P61080}/hello.txt)
check_http "several ranges 200"  "200 OK" "$resp"
check_http "several ranges full" "Content-Length: 18" "$resp"
# Range is defined for GET alone
resp=$(curl -si --max-time 2 -I -H 'Range: bytes=0-4' http://127.0.0.1:${P61080}/hello.txt)
check_http "HEAD ignores range"  "200 OK" "$resp"
check_http "HEAD full length"    "Content-Length: 18" "$resp"
# the conditionals still win over Range
resp=$(curl -si --max-time 2 -r 0-4 -H "If-None-Match: $etag" http://127.0.0.1:${P61080}/hello.txt)
check_http "range vs 304"        "304 Not Modified" "$resp"
# If-Range: the range only with a strong validator match
resp=$(curl -si --max-time 2 -r 0-4 -H "If-Range: $etag" http://127.0.0.1:${P61080}/hello.txt)
check_http "if-range match 206"  "206 Partial Content" "$resp"
resp=$(curl -si --max-time 2 -r 0-4 -H 'If-Range: "stale"' http://127.0.0.1:${P61080}/hello.txt)
check_http "if-range stale 200"  "200 OK" "$resp"
resp=$(curl -si --max-time 2 -r 0-4 -H "If-Range: W/$etag" http://127.0.0.1:${P61080}/hello.txt)
check_http "if-range weak 200"   "200 OK" "$resp"
resp=$(curl -si --max-time 2 -r 0-4 -H "If-Range: $lastmod" http://127.0.0.1:${P61080}/hello.txt)
check_http "if-range date 206"   "206 Partial Content" "$resp"
resp=$(curl -si --max-time 2 -r 0-4 -H 'If-Range: Wed, 01 Jan 2020 00:00:00 GMT' http://127.0.0.1:${P61080}/hello.txt)
check_http "if-range old date 200" "200 OK" "$resp"
# ranges hold on big files and on pre-compressed variants
n=$(curl -s --max-time 5 -r 90000-99999 http://127.0.0.1:${P61080}/big.txt | tr -d 'B' | wc -c)
[ "$n" -eq 0 ] && [ "$(curl -s --max-time 5 -r 90000-99999 http://127.0.0.1:${P61080}/big.txt | wc -c)" -eq 10000 ]
check "range into big file" $?
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: br' -r 0-1 http://127.0.0.1:${P61080}/enc.txt)
check_http "variant range slices variant" "Content-Range: bytes 0-1/10" "$resp"
check_http "variant range body"  "br" "$resp"
# two ranged requests ride one keep-alive connection
before=$(grep -c "accepted connection" "$LOG")
curl -s --max-time 4 -r 0-4 \
    http://127.0.0.1:${P61080}/hello.txt http://127.0.0.1:${P61080}/hello.txt >/dev/null
after=$(grep -c "accepted connection" "$LOG")
[ $((after - before)) -eq 1 ]
check "206 keep-alive single accept" $?
grep -qF '"GET /hello.txt HTTP/1.1" 206 5' "$LOG"
check "request log 206" $?
grep -qF '"GET /hello.txt HTTP/1.1" 416 0' "$LOG"
check "request log 416" $?

# --- virtual hosts: 61080 is shared by one.test (default) and three.test ---
resp=$(curl -s --max-time 2 -H "Host: three.test" http://127.0.0.1:${P61080}/page.html)
check_http "vhost three.test"  "subdirectory page" "$resp"
resp=$(curl -s --max-time 2 -H "Host: three.test:${P61080}" http://127.0.0.1:${P61080}/page.html)
check_http "vhost host:port"   "subdirectory page" "$resp"
resp=$(curl -s --max-time 2 -H "Host: unknown.test" http://127.0.0.1:${P61080}/hello.txt)
check_http "vhost default"     "hello from linnea" "$resp"

# --- percent-decoding ---
resp=$(curl -s --max-time 2 "http://127.0.0.1:${P61080}/a%20b.txt")
check_http "decode space"      "space file" "$resp"
resp=$(curl -s --max-time 2 "http://127.0.0.1:${P61080}/sub%2Fpage.html")
check_http "decode slash"      "subdirectory page" "$resp"
check_http "encoded traversal" "400 Bad Request" "$(raw_http 'GET /%2e%2e/secret HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "bad escape"        "400 Bad Request" "$(raw_http 'GET /%zz HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "encoded NUL"       "400 Bad Request" "$(raw_http 'GET /%00 HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"

# --- path normalization (raw, curl normalizes dot segments itself) ---
check_http "double slash"   "hello from linnea" "$(raw_http 'GET //hello.txt HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "dot segment"    "hello from linnea" "$(raw_http 'GET /./hello.txt HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "dotdot resolve" "hello from linnea" "$(raw_http 'GET /sub/../hello.txt HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "dotdot to dir"  "linnea index page" "$(raw_http 'GET /sub/.. HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "above root"     "400 Bad Request" "$(raw_http 'GET /a/../../x HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"

# --- request bodies ---
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one.test\r\nContent-Length: 5\r\n\r\nXXXXXGET /hello.txt HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')
n=$(printf '%s' "$resp" | grep -c "200 OK")
[ "$n" -eq 2 ]
check "body discarded, keep-alive" $?
# Chunked bodies used to be 501 and this test asserted it. Receiving and
# decoding the coding is a MUST (RFC 9112 7.1), so the expectation moves with
# the behaviour: a complete chunked body is served, and a coding we genuinely do
# not implement is what keeps the 501.
check_http "chunked body decoded and served" "200 OK" "$(raw_http 'GET / HTTP/1.1\r\nHost: one.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n')"
check_http "an unimplemented coding is still 501" "501 Not Implemented" "$(raw_http 'GET / HTTP/1.1\r\nHost: one.test\r\nTransfer-Encoding: gzip\r\nConnection: close\r\n\r\n')"
# A static location cannot stream a body, so one it cannot buffer with the
# head is refused; a proxy location streams the same body instead (below).
check_http "body too large 413" "413 Content Too Large" "$(raw_http 'GET / HTTP/1.1\r\nHost: one.test\r\nContent-Length: 20000\r\n\r\n')"

# --- protocol errors and traversal (raw, curl normalizes paths) ---
check_http "http 400" "400 Bad Request" "$(raw_http 'GARBAGE\r\n\r\n')"
# h1-11: HTTP/1.0 is SERVED, not refused. 505 is defined for a MAJOR version the
# server does not support (RFC 9110 15.6.6) and 1.0 shares major version 1 with
# 1.1, so refusing it was both a misuse of the code and an operational trap --
# health checkers and `curl -0` speak 1.0, and a 505 reads like a protocol fault
# rather than a version default. Only a major version we do not implement is 505
# now; a higher MINOR version is processed as 1.1, which is what RFC 9112 2.5
# asks for.
check_http "http/1.0 served" "200 OK" "$(raw_http 'GET /hello.txt HTTP/1.0\r\nHost: one.test\r\n\r\n')"
check_http "http/1.0 without Host served" "200 OK" "$(raw_http 'GET /hello.txt HTTP/1.0\r\n\r\n')"
check_http "http/1.1 without Host still 400" "400 Bad Request" "$(raw_http 'GET /hello.txt HTTP/1.1\r\n\r\n')"
check_http "http/1.2 processed as 1.1" "200 OK" "$(raw_http 'GET /hello.txt HTTP/1.2\r\nHost: one.test\r\n\r\n')"
check_http "http 505" "505 HTTP Version Not Supported" "$(raw_http 'GET / HTTP/2.0\r\nHost: one.test\r\nConnection: close\r\n\r\n')"

# 1.0 has no persistent connections unless the client asks for one, and "close"
# wins wherever it appears in the list (9.1) -- applying the tokens in order
# would let `close, keep-alive` reopen a connection the client had finished with.
check_http "http/1.0 defaults to close" "Connection: close" "$(raw_http 'GET /hello.txt HTTP/1.0\r\nHost: one.test\r\n\r\n')"
check_http "http/1.0 keep-alive honoured" "Connection: keep-alive" "$(raw_http 'GET /hello.txt HTTP/1.0\r\nHost: one.test\r\nConnection: keep-alive\r\n\r\n')"
check_http "http/1.0 close beats keep-alive whatever the order" "Connection: close" "$(raw_http 'GET /hello.txt HTTP/1.0\r\nHost: one.test\r\nConnection: close, keep-alive\r\n\r\n')"
check_http "http/1.1 close beats keep-alive whatever the order" "Connection: close" "$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one.test\r\nConnection: close, keep-alive\r\n\r\n')"

# two requests on one 1.0 connection, which only works if keep-alive was real
ka10=$(raw_http 'GET /hello.txt HTTP/1.0\r\nHost: one.test\r\nConnection: keep-alive\r\n\r\nGET /hello.txt HTTP/1.0\r\nHost: one.test\r\nConnection: close\r\n\r\n')
[ "$(printf '%s' "$ka10" | grep -c '^HTTP/1.1 200')" = "2" ]
check "http/1.0 keep-alive serves a second request on the same connection" $?

# RFC 9110 10.1.1: a 100 (Continue) MUST NOT be sent to a 1.0 client, which would
# read the interim status as the final one. 1.1 must still get it.
exp11=$(raw_http 'POST /hello.txt HTTP/1.1\r\nHost: one.test\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n')
printf '%s' "$exp11" | grep -q '100 Continue'
check "http/1.1 Expect still draws 100 Continue" $?
# `grep -qv` would be the wrong test here: it asks "is there a line that does not
# match", which is FALSE for the empty response that passing actually produces --
# a 1.0 client gets nothing at all and the server waits for the body.
exp10=$(raw_http 'POST /hello.txt HTTP/1.0\r\nHost: one.test\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n')
! printf '%s' "$exp10" | grep -q '100 Continue'
check "http/1.0 Expect draws no 100 Continue" $?
check_http "traversal blocked" "400 Bad Request" "$(raw_http 'GET /../secret HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"

# --- video MIME types (Q129): a .mp4 served as application/octet-stream is
# not played by a browser's <video> element, so the type is what makes a
# media file usable at all. Range handling is exercised elsewhere; what is
# checked here is the type, on a plain GET and on a 206.
printf 'not really a video' > $WWW/clip.mp4
resp=$(raw_http 'GET /clip.mp4 HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "mime: .mp4 is video/mp4" "Content-Type: video/mp4" "$resp"

# Q130: the types a modern site cannot do without. The first three are hard
# failures rather than cosmetics — WebAssembly refuses to instantiate without
# application/wasm, an ES module served as octet-stream is rejected outright
# under the nosniff we send, and a .htm answered as octet-stream downloads
# instead of rendering. Both tables are checked, since h1 and h2/h3 keep
# separate ones and a type added to only one is the likely mistake.
mime_probe wasm        application/wasm
mime_probe mjs         text/javascript
mime_probe htm         text/html
mime_probe woff2       font/woff2
mime_probe webp        image/webp
mime_probe avif        image/avif
mime_probe mp3         audio/mpeg
mime_probe pdf         application/pdf
mime_probe webmanifest application/manifest+json
mime_probe js          text/javascript
# Q131: the text types declare UTF-8. A page carries <meta charset> and is
# fine either way, but a .txt or .csv without it is left to whatever the
# browser guesses. Not on application/json: RFC 8259 defines JSON as UTF-8
# and its media type has no charset parameter at all.
mime_probe txt  'text/plain; charset=utf-8'
mime_probe csv  'text/csv; charset=utf-8'
mime_probe css  'text/css; charset=utf-8'
resp=$(raw_http 'GET /probe.json HTTP/1.1\r\nHost: one.test\r\n\r\n')
printf 'x' > $WWW/probe.json
resp=$(raw_http 'GET /probe.json HTTP/1.1\r\nHost: one.test\r\n\r\n')
printf '%s' "$resp" | grep -qi 'charset' && json_charset=1 || json_charset=0
[ "$json_charset" = 0 ]
check "mime: application/json carries no charset" $?
rm -f $WWW/probe.json
resp=$(raw_http 'GET /clip.mp4 HTTP/1.1\r\nHost: one.test\r\nRange: bytes=0-3\r\n\r\n')
check_http "mime: a 206 keeps the video type" "Content-Type: video/mp4" "$resp"
check_http "mime: the 206 is a real partial" "206 Partial Content" "$resp"
rm -f $WWW/clip.mp4

# --- request-target forms (Q127, RFC 9112 3.2). Only origin-form used to
# survive: absolute-form and "OPTIONS *" reached the path normalizer and came
# back 400. A server MUST accept absolute-form, and the authority it carries
# — not the Host header — identifies the resource.
resp=$(raw_http 'GET http://one.test/hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: absolute-form served" "hello from linnea" "$resp"
resp=$(raw_http 'GET https://one.test/hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: absolute-form (https scheme) served" "hello from linnea" "$resp"
resp=$(raw_http 'GET http://one.test HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: absolute-form with no path is the root" "200 OK" "$resp"
# the target's authority wins over Host: three.test has its own root, which
# holds no hello.txt, so routing by it is visible as a 404
resp=$(raw_http 'GET http://three.test/hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: absolute-form authority beats Host" "404" "$resp"
resp=$(raw_http 'GET http:///hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: absolute-form with an empty authority is 400" "400 Bad Request" "$resp"
# an HTTP/1.1 client must still send Host, even in absolute-form
resp=$(raw_http 'GET http://one.test/hello.txt HTTP/1.1\r\n\r\n')
check_http "target: absolute-form still requires a Host line" "400 Bad Request" "$resp"
resp=$(raw_http 'OPTIONS * HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: OPTIONS * answered" "200 OK" "$resp"
check_http "target: OPTIONS * lists the methods" "Allow: GET, HEAD, OPTIONS" "$resp"
resp=$(raw_http 'GET * HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: asterisk with any other method is 400" "400 Bad Request" "$resp"
# the asterisk form used to be answered before the Host rules ran, so it was the
# one request that could arrive with no Host or two of them and still get a 200
resp=$(raw_http 'OPTIONS * HTTP/1.1\r\n\r\n')
check_http "target: OPTIONS * without a Host is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'OPTIONS * HTTP/1.1\r\nHost: one.test\r\nHost: evil.test\r\n\r\n')
check_http "target: OPTIONS * with two Hosts is 400" "400 Bad Request" "$resp"
# ...and the same here: the body is decoded, so OPTIONS * answers about the
# server as it always should have. The 501 was the coding being refused.
resp=$(raw_http 'OPTIONS * HTTP/1.1\r\nHost: one.test\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n')
check_http "target: OPTIONS * with a chunked body is answered" "200 OK" "$resp"

# --- the method is a token (RFC 9110 9.1). The request-line parse only bounded
# it to printable ASCII, so every delimiter got through — including the double
# quote, which the access line writes the method inside, splitting its own
# quoted field. An unknown but well-formed method still parses as a method.
#
# Its ANSWER is 501, not 405: 15.6.2 makes 501 "the appropriate response when
# the server does not recognize the request method", where 405 says the method
# is known and merely not allowed here. These checks asserted 405 for both,
# which told a client PROPFIND was a real method this resource declines.
resp=$(raw_http 'PROPFIND /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "method: an unknown token method is 501, not 400" "501 Not Implemented" "$resp"
# RFC 9110 15.5.6: a 405 must name what the resource does take — so it is asked
# with a method we DO recognise
resp=$(raw_http 'POST /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "method: a known method gets 405" "405 Method Not Allowed" "$resp"
check_http "method: the 405 carries Allow" "Allow: GET, HEAD" "$resp"
resp=$(raw_http '!#$%&\x27*+-.^_`|~ /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "method: every tchar punctuation is still a method" "501 Not Implemented" "$resp"
resp=$(raw_http 'GE"T /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "method: a double quote is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'GE/T /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "method: a delimiter is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'GE\x1bT /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "method: a control byte is 400" "400 Bad Request" "$resp"
# a method is case-sensitive (RFC 9110 9.1), so "get" is not GET — and not a
# method we recognise at all, which is 501
resp=$(raw_http 'get /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "method: lowercase get is 501, not a served file" "501 Not Implemented" "$resp"
# None of those reached the access log, which is what the quote could break.
# Matched through cat -v so the ESC shows as ^[, and with -F so the quote and
# the brackets are literal — "GE alone would match every ordinary GET line.
! cat -v "$LOG" | grep -qF -e '"GE"T' -e '"GE/T' -e '"GE^[T'
check "method: no malformed method reaches the access log" $?

# --- Host header rules (Q123, RFC 9112 3.2): every request we accept is
# HTTP/1.1, so exactly one Host field line is mandatory and its value must
# look like an authority. A missing or repeated Host used to be served
# normally — and a second Host is a smuggling primitive, since an
# intermediary may route on the other one.
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "host: one Host serves"  "200 OK" "$resp"
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\n\r\n')
check_http "host: missing Host is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one.test\r\nHost: evil.test\r\n\r\n')
check_http "host: duplicate Host is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one.test\r\nHost: one.test\r\n\r\n')
check_http "host: repeated identical Host is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost:\r\n\r\n')
check_http "host: empty Host is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one test\r\n\r\n')
check_http "host: Host with a space is 400" "400 Bad Request" "$resp"
resp=$(raw_http "GET /hello.txt HTTP/1.1\r\nHost: one.test:${P61080}\r\n\r\n")
check_http "host: Host with a port serves" "200 OK" "$resp"
resp=$(raw_http "GET /hello.txt HTTP/1.1\r\nHost: [::1]:${P61080}\r\n\r\n")
check_http "host: IPv6-literal Host serves" "200 OK" "$resp"
# the trailing OWS a field value may carry is trimmed before validation
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one.test\t\r\n\r\n')
check_http "host: trailing OWS trimmed, not rejected" "200 OK" "$resp"
# a proxied location is routed only after the Host check
resp=$(raw_http 'GET /api/simple HTTP/1.1\r\n\r\n')
check_http "host: missing Host on a proxy location is 400" "400 Bad Request" "$resp"

# --- request log lines (with peer address) ---
grep -qE 'request one\.test from 127\.0\.0\.1:[0-9]+ "GET /hello\.txt HTTP/1\.1" 200 18' "$LOG"
check "request log 200" $?
grep -qE 'request three\.test from 127\.0\.0\.1:[0-9]+ "GET /page\.html HTTP/1\.1" 200' "$LOG"
check "request log vhost" $?
grep -qE '"GET /a%20b\.txt HTTP/1\.1" 200' "$LOG"
check "request log raw target" $?
grep -qF '"GET /no-such-file HTTP/1.1" 404 0' "$LOG"
check "request log 404" $?
grep -qF '"POST /hello.txt HTTP/1.1" 405 0' "$LOG"
check "request log 405" $?
grep -qE '^\[20[0-9]{2}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\] request' "$LOG"
check "log timestamps" $?

# --- keep-alive: two requests, one connection (count accepts in the log) ---
before=$(grep -c "accepted connection" "$LOG")
resp=$(curl -s --max-time 4 http://127.0.0.1:${P61080}/hello.txt http://127.0.0.1:${P61080}/index.html)
after=$(grep -c "accepted connection" "$LOG")
check_http "keep-alive body 1" "hello from linnea" "$resp"
check_http "keep-alive body 2" "linnea index page" "$resp"
[ $((after - before)) -eq 1 ]
check "keep-alive single accept" $?

# --- pipelined requests in one write ---
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\nGET /hello.txt HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')
n=$(printf '%s' "$resp" | grep -c "200 OK")
[ "$n" -eq 2 ]
check "pipelined requests" $?

# --- idle timeout: configured to 2s in listen.json ---
start=$SECONDS
if timeout 6 bash -c "exec 3<>/dev/tcp/127.0.0.1/${P61080}; cat <&3" >/dev/null 2>&1; then
    elapsed=$((SECONDS - start))
    [ "$elapsed" -ge 1 ] && [ "$elapsed" -le 4 ]
    check "configured idle timeout (${elapsed}s)" $?
else
    check "configured idle timeout (connection not closed)" 1
fi

grep -qE "accepted connection on 127\.0\.0\.1:${P61080} from 127\.0\.0\.1:[0-9]+ \(fd " "$LOG"
check "accept log line" $?

# --- proxying: /api -> the test backend, /down -> nothing listening ---
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/simple)
check_http "proxy body"          "backend body" "$resp"
check_http "proxy status"        "200 OK" "$resp"
check_http "proxy content-length" "Content-Length: 12" "$resp"
check_http "proxy keeps alive"   "Connection: keep-alive" "$resp"

# the prefix is not stripped and the query survives: the backend echoes the target
resp=$(curl -s --max-time 3 "http://127.0.0.1:${P61080}/api/target?x=1&y=2")
check_http "proxy target forwarded" "/api/target?x=1&y=2" "$resp"

# the client's Connection header is replaced, everything else passes through
resp=$(curl -s --max-time 3 -H 'X-Test: abc' -H 'Connection: keep-alive' \
    http://127.0.0.1:${P61080}/api/headers)
check_http "proxy forwards headers" "X-Test: abc" "$resp"
check_http "proxy forwards host"    "Host: 127.0.0.1:${P61080}" "$resp"
check_http "proxy closes upstream"  "Connection: close" "$resp"

resp=$(curl -s --max-time 3 -d 'hello body' http://127.0.0.1:${P61080}/api/echo)
check_http "proxy forwards body" "hello body" "$resp"

# ...but a field the client's own Connection names is hop-by-hop and MUST be
# removed before forwarding (RFC 9110 7.6.1). Only Connection and Expect were
# dropped, so a client could mark any field hop-by-hop and have it delivered to
# the backend anyway — the header-smuggling shape that rule exists to close.
if extensive; then
    timeout 60 python3 test/tls/h1_proxy_hop_by_hop.py ${P61080} >/dev/null 2>&1
    check "proxy removes hop-by-hop fields, both directions" $?
else
    skip "proxy removes hop-by-hop fields, both directions -- 20s"
fi

# RFC 9110 7.6.3 MUST: a proxy names itself and the protocol it received on, in
# each message it forwards. Without it a proxied request is indistinguishable
# from a direct one — no loop detection, and no way to tell which hop
# transformed a message.
timeout 60 python3 test/tls/proxy_via.py ${P61080} >/dev/null 2>&1
check "proxy adds Via to the request and the response" $?

# RFC 9110 5.6.7 MUST: all three HTTP-date formats parse. Only IMF-fixdate did,
# so a conditional request carrying an obsolete form was answered
# unconditionally — the client got the whole body instead of its 304.
timeout 60 python3 test/tls/http_date_formats.py ${P61080} >/dev/null 2>&1
check "all three HTTP-date formats are accepted" $?

# RFC 9110 13.1.1 / 13.1.4: If-Match and If-Unmodified-Since were never read, so
# a request carrying one was answered as though it had no condition at all —
# the lost update those fields exist to prevent. 13.2.2 also fixes the order:
# a failing If-Match is a 412 even when an If-None-Match would have said 304.
timeout 60 python3 test/tls/preconditions.py ${P61080} >/dev/null 2>&1
check "If-Match and If-Unmodified-Since are evaluated" $?

# RFC 9112 9.1: Connection is a token LIST and `close` may sit anywhere in it.
# Only a value that was entirely "close" counted, so `keep-alive, close` was
# answered `Connection: keep-alive` and the socket held to the idle timeout.
if extensive; then
    timeout 60 python3 test/tls/connection_close_token.py ${P61080} >/dev/null 2>&1
    check "Connection: close is honoured anywhere in the list" $?
else
    skip "Connection: close is honoured anywhere in the list -- 8s"
fi

# RFC 9110 6.6.1: Date on everything outside 1xx/5xx. The canned blobs are
# assembled ahead of time, so they shipped without one while every dynamically
# built response had it. RFC 9112 9.6: and a response that closes must say so —
# the OPTIONS * blob closed while claiming, in a comment, that it did not.
timeout 60 python3 test/tls/canned_response_headers.py ${P61080} >/dev/null 2>&1
check "canned responses carry Date and announce a close" $?

# RFC 9110 10.1.1 MUST: answer a 100-continue expectation with 100 or a final
# status. The field was never inspected, so the server waited for a body the
# client was withholding while the client waited for permission to send it —
# a full second added to every such request, for clients that recover at all.
timeout 60 python3 test/tls/expect_continue.py ${P61080} >/dev/null 2>&1
check "Expect: 100-continue is answered" $?

# Chunked request bodies (RFC 9112 7.1 MUST). Any Transfer-Encoding at all used
# to be 501, so every client that sends a body of unknown length up front was
# refused: curl -T -, fetch() with a ReadableStream, most libraries handed a
# stream. The arrival-pattern cases are the ones that matter — a body comes in
# as many reads as the network likes.
if extensive; then
    timeout 120 python3 test/tls/h1_chunked_request.py ${P61080} >/dev/null 2>&1
    check "h1 decodes chunked request bodies" $?
else
    skip "h1 decodes chunked request bodies -- 20s, a sweep of arrival patterns"
fi

# a HEAD response is head-only even though the backend sends Content-Length:
# waiting for that body would hang until the idle timeout
resp=$(curl -si --max-time 3 -I http://127.0.0.1:${P61080}/api/simple)
check_http "proxy HEAD length"   "Content-Length: 12" "$resp"
check_http "proxy HEAD no hang"  "200 OK" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/204)
check_http "proxy 204 no body"   "204 No Content" "$resp"

# chunked and close-delimited bodies have no length we can pass on, so the
# client connection has to close to delimit them
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/chunked)
check_http "proxy chunked body"  "chunked body" "$resp"
check_http "proxy chunked framing" "Transfer-Encoding: chunked" "$resp"
check_http "proxy chunked closes" "Connection: close" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/eof)
check_http "proxy eof body"      "eof delimited body" "$resp"
check_http "proxy eof closes"    "Connection: close" "$resp"

# a body bigger than the relay buffer takes several upstream reads
n=$(curl -s --max-time 5 http://127.0.0.1:${P61080}/api/big | wc -c)
[ "$n" -eq 40000 ]
check "proxy large body ($n bytes)" $?

resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/http10)
check_http "proxy 1.0 upstream"  "HTTP/1.1 200 OK" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/301)
check_http "proxy passes status" "301 Moved Permanently" "$resp"
check_http "proxy passes header" "Location: /elsewhere" "$resp"

# proxied and static requests share one keep-alive connection
before=$(grep -c "accepted connection" "$LOG")
resp=$(curl -s --max-time 4 http://127.0.0.1:${P61080}/api/simple http://127.0.0.1:${P61080}/hello.txt)
after=$(grep -c "accepted connection" "$LOG")
check_http "proxy then static body" "hello from linnea" "$resp"
[ $((after - before)) -eq 1 ]
check "proxy keep-alive single accept" $?

# --- proxy failures ---
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/down/x)
check_http "proxy refused 502"   "502 Bad Gateway" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/garbage)
check_http "proxy garbage 502"   "502 Bad Gateway" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/bighead)
check_http "proxy huge head 502" "502 Bad Gateway" "$resp"
# contradictory upstream framing must never reach the client: forwarding
# both would let a compromised backend split the next keep-alive response
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/tecl)
check_http "proxy TE+CL 502"     "502 Bad Gateway" "$resp"

# The upstream deadline is its own key. One `timeout` governed both halves, so
# a deployment could not hold a client connection open longer than it was
# willing to wait for a backend -- or the reverse, which is the common one.
# This fixture is the case that could not be expressed: timeout 2, backend
# deadline 10, against /api/slow, which sleeps 4s. Before proxy_timeout the
# client idle timeout cut it at 2s and the answer was a 504.
start_server $CFG/proxy-timeout.json
ptmo_pid=$SRV_PID
ptmo=$(curl -s --max-time 20 -o /dev/null -w '%{http_code}' \
       http://127.0.0.1:${P61466}/api/slow)
[ "$ptmo" = "200" ]
check "proxy_timeout outlives a shorter client timeout ($ptmo, backend sleeps 4s)" $?
# ...and the ordinary path through the same server still answers, so the check
# above cannot pass on a build that simply stopped timing anything out.
ptmo2=$(curl -s --max-time 10 http://127.0.0.1:${P61466}/api/simple)
[ "$ptmo2" = "backend body" ]
check "proxy_timeout fixture serves an ordinary proxied request ($ptmo2)" $?
kill $ptmo_pid 2>/dev/null
wait $ptmo_pid 2>/dev/null

# error_log splits the diagnostics from the request record. One file held both,
# so the stream you want when something is wrong was interleaved with thousands
# of access lines an hour. The split is nginx's: access_log is the requests,
# error_log is everything else.
rm -f $RUNDIR/linnea-split-acc.log $RUNDIR/linnea-split-err.log
start_server $CFG/error-log.json
elog_pid=$SRV_PID
# BOTH protocols this fixture speaks. h1 and h2 write their access records
# through different code, and marking only one of them is exactly how this
# shipped broken the first time: the manual check used h2, so h1's own writer
# went unnoticed until the suite ran.
curl -s -o /dev/null --max-time 5 --http1.1 https://localhost:${P61467}/hello.txt --cacert $CA --resolve localhost:${P61467}:127.0.0.1
curl -s -o /dev/null --max-time 5 --http2  https://localhost:${P61467}/nope     --cacert $CA --resolve localhost:${P61467}:127.0.0.1
sleep 0.3
# the access log holds the request records and NOTHING else
# `grep -c` PRINTS 0 and EXITS 1 when nothing matches, so "|| echo 0" appends a
# second zero and the variable becomes "0\n0" -- which fails every comparison
# and truncates the label. "|| true" keeps grep's own count.
#
# And the property, not the count: start_server makes its own readiness request,
# so how many records land here is the harness's business. What must hold is
# that the access log contains request records and NOTHING else, from both
# protocols.
acc_req=$(grep -c "request localhost" $RUNDIR/linnea-split-acc.log 2>/dev/null || true)
acc_other=$(grep -vc "request localhost" $RUNDIR/linnea-split-acc.log 2>/dev/null || true)
acc_protos=$(grep -oE "HTTP/[0-9.]+" $RUNDIR/linnea-split-acc.log 2>/dev/null | sort -u | tr '\n' ' ')
[ "${acc_req:-0}" -ge 2 ] && [ "${acc_other:-1}" = "0" ] && [ "$acc_protos" = "HTTP/1.1 HTTP/2 " ]
check "error_log: the access log holds only request records, from both protocols ($acc_req req, $acc_other other: $acc_protos)" $?
# ...and the diagnostics went to the other file, with no request lines in it
err_life=$(grep -c "accepted connection" $RUNDIR/linnea-split-err.log 2>/dev/null || true)
err_req=$(grep -c "request localhost" $RUNDIR/linnea-split-err.log 2>/dev/null || true)
[ "${err_life:-0}" -ge 2 ] && [ "${err_req:-1}" = "0" ]
check "error_log: the diagnostics went to the other file ($err_life lifecycle, $err_req req)" $?

# A dead worker must say HOW it died. wait4 hands the master the status and the
# master used to log only the pid, so nine worker deaths in one day (2026-08-14)
# could not be told from nine clean exits -- and those want opposite
# investigations. The worker's OWN fatal message went to stderr, which under
# systemd is a journal an unprivileged operator cannot read, on a unit whose
# AmbientCapabilities also forbid a core dump. Both halves are asserted here
# because either alone leaves the cause unreadable.
elog_worker=$(workers_of_now $elog_pid | awk '{print $1}')
kill -9 $elog_worker 2>/dev/null
for i in $(seq 1 40); do
    grep -q "exited on signal" $RUNDIR/linnea-split-err.log 2>/dev/null && break
    sleep 0.1
done
grep -q "worker $elog_worker exited on signal 9, respawning" $RUNDIR/linnea-split-err.log
check "a worker killed by a signal is logged with that signal" $?
# ...on the error stream, where diagnostics live -- not among the request records
! grep -q "exited on signal" $RUNDIR/linnea-split-acc.log 2>/dev/null
check "a worker death is a diagnostic, not an access record" $?
# A memory fault must report WHERE, not merely that it happened. The master's
# line gives the signal; this gives the instruction. Without it a segfault on
# this unit is unattributable -- AmbientCapabilities clears the dumpable flag,
# so production cannot leave a core however LimitCORE is set, and seven
# segfaults on 2026-08-14 produced none.
#
# Asserted because the install can fail SILENTLY: the first attempt at wiring
# it never inserted the call at all (the target line ended in a continuation
# backslash), the handler never ran, and the only symptom was a missing line
# that nothing was looking for.
elog_worker3=$(workers_of_now $elog_pid | awk '{print $1}')
kill -11 $elog_worker3 2>/dev/null
for i in $(seq 1 40); do
    grep -q "fatal: SIGSEGV" $RUNDIR/linnea-split-err.log 2>/dev/null && break
    sleep 0.1
done
crash_line=$(grep "fatal: SIGSEGV" $RUNDIR/linnea-split-err.log 2>/dev/null | tail -1)
case "$crash_line" in
    *"fatal: SIGSEGV addr=0x"*"rip=0x"*"rsp=0x"*) true ;;
    *) false ;;
esac
check "a memory fault reports addr, rip and rsp before dying (${crash_line:-nothing logged})" $?
# and the rip must be a real code address -- a zero or a truncated field would
# satisfy the shape above while naming nothing
crash_rip=$(printf '%s' "$crash_line" | grep -oE "rip=0x[0-9a-f]{16}" | cut -d= -f2)
[ -n "$crash_rip" ] && [ "$crash_rip" != "0x0000000000000000" ]
check "the reported rip is a real address ($crash_rip)" $?
# the handler must not CHANGE the outcome: the worker still dies of signal 11
for i in $(seq 1 40); do
    grep -q "exited on signal 11" $RUNDIR/linnea-split-err.log 2>/dev/null && break
    sleep 0.1
done
grep -q "worker $elog_worker3 exited on signal 11, respawning" $RUNDIR/linnea-split-err.log
check "a reported fault still kills the worker with its own signal" $?

sleep 1.3
# The control: a worker that exits of its own accord must read DIFFERENTLY, or
# the line cannot answer the only question it exists to answer.
#
# Wait out the master's spawn-storm guard first. A worker that exits WITHOUT a
# signal within one second of being spawned is treated as a startup error that
# would repeat for ever, so the master gives up (.storm) instead of logging and
# respawning -- and the worker respawned a moment ago by the kill -9 above is
# well inside that window. Sending the SIGTERM immediately makes the master
# exit and produces no status line at all, which is the server behaving
# correctly and the test asking the wrong question.
sleep 1.3
elog_worker2=$(workers_of_now $elog_pid | awk '{print $1}')
kill -TERM $elog_worker2 2>/dev/null
for i in $(seq 1 40); do
    grep -q "exited with status" $RUNDIR/linnea-split-err.log 2>/dev/null && break
    sleep 0.1
done
grep -q "worker $elog_worker2 exited with status 0, respawning" $RUNDIR/linnea-split-err.log
check "a worker that exits on its own is logged with its status, not a signal" $?

kill $elog_pid 2>/dev/null
wait $elog_pid 2>/dev/null

# rate_limit meters REQUESTS, which is what max_per_ip cannot: h2 and h3 allow
# 100 streams per connection, so a connection cap barely bounds the request
# rate. Every protocol must be metered -- a limit two of the three walk past is
# a control with a hole, and it is the same address either way, so all three
# share ONE bucket. Exact counts are timing (the bucket refills while the loop
# runs), so this asserts the property: some allowed, some refused, on each.
rm -f $RUNDIR/linnea-rl.log
start_server $CFG/rate-limit.json
rl_pid=$SRV_PID
rl_burst "h1" curl -sS -o /dev/null -w '%{http_code}' --max-time 5 --http1.1 \
    --cacert $CA --resolve localhost:${P61468}:127.0.0.1 https://localhost:${P61468}/hello.txt
rl_burst "h2" curl -sS -o /dev/null -w '%{http_code}' --max-time 5 --http2 \
    --cacert $CA --resolve localhost:${P61468}:127.0.0.1 https://localhost:${P61468}/hello.txt
if [ -x "$CURLH3" ] && "$CURLH3" -V 2>/dev/null | grep -q HTTP3; then
    rl_burst "h3" "$CURLH3" --http3-only -s -o /dev/null -w '%{http_code}' --max-time 15 \
        --cacert $CA --resolve localhost:${P61468}:127.0.0.1 https://localhost:${P61468}/hello.txt
else
    check "rate_limit meters h3 (skipped: no HTTP/3 curl)" 0
fi
# What the SERVER recorded, not what the client saw. The client's view cannot
# tell 429 from 431, and it was 431 in the log on the first cut: the wire
# response was parameterised and the access line left hardcoded. h3 was worse —
# it wrote the access line from the SHARED log block, so a refusal carried the
# previous request's method and target.
rl_logged=$(grep -cE '"- - HTTP/[0-9.]+" 429 ' $RUNDIR/linnea-rl.log 2>/dev/null || true)
rl_wrong=$(grep -cE ' (431|200) $' /dev/null 2>/dev/null || true)
rl_mislabelled=$(grep -c ' 431 ' $RUNDIR/linnea-rl.log 2>/dev/null || true)
[ "${rl_logged:-0}" -ge 2 ] && [ "${rl_mislabelled:-1}" = "0" ]
check "rate_limit logs a refusal as 429, with no method or target ($rl_logged recorded, $rl_mislabelled mislabelled 431)" $?

# ...and it recovers: a client that waits is served again rather than stuck
sleep 1.3
rl_again=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 --cacert $CA \
    --resolve localhost:${P61468}:127.0.0.1 https://localhost:${P61468}/hello.txt)
[ "$rl_again" = "200" ]
check "rate_limit refills: a client that waits is served again ($rl_again)" $?
kill $rl_pid 2>/dev/null
wait $rl_pid 2>/dev/null
# The control, and the one that matters for every deployment that has not asked
# for this: with the key unset nothing is metered at all. The fixture above is
# the only one in the suite that sets it, so any other server serving a burst
# would do -- assert it explicitly rather than by implication.
start_server $CFG/error-log.json      # no rate_limit key
rlctl_pid=$SRV_PID
rlctl=0
for i in $(seq 1 25); do
    c=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 --cacert $CA \
        --resolve localhost:${P61467}:127.0.0.1 https://localhost:${P61467}/hello.txt)
    [ "$c" = "200" ] && rlctl=$((rlctl+1))
done
[ "$rlctl" = "25" ]
check "rate_limit unset meters nothing ($rlctl/25 served)" $?
kill $rlctl_pid 2>/dev/null
wait $rlctl_pid 2>/dev/null
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/cljunk)
check_http "proxy bad CL 502"    "502 Bad Gateway" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/clpad)
check_http "proxy CL whitespace" "valid" "$resp"
# Expect must not be forwarded: the body is already buffered, and an
# interim 100 Continue would be parsed as the response itself
resp=$(raw_http 'POST /api/expect HTTP/1.1\r\nHost: one.test\r\nContent-Length: 5\r\nExpect: 100-continue\r\nConnection: close\r\n\r\nHELLO')
check_http "proxy drops Expect"  "real" "$resp"
printf '%s' "$resp" | grep -qF "100 Continue"
[ $? -ne 0 ]
check "proxy no interim 100 leak" $?
# the backend sleeps 4s; the config's timeout is 2s
start=$SECONDS
resp=$(curl -si --max-time 8 http://127.0.0.1:${P61080}/api/slow)
elapsed=$((SECONDS - start))
check_http "proxy slow 504"      "504 Gateway Timeout" "$resp"
[ "$elapsed" -le 4 ]
check "proxy 504 on time (${elapsed}s)" $?
# a body cut short of its Content-Length must not look like a clean end
curl -s --max-time 3 http://127.0.0.1:${P61080}/api/truncated >/dev/null 2>&1
grep -qF ': upstream closed early' "$LOG"
check "proxy truncated body" $?

# --- large uploads: a body too large to buffer with the head is captured in
# full (on disk, past what fits in memory) and only then forwarded, so it is
# bounded by max_body rather than by in_buf ---
python3 -c "
import random, sys
random.seed(11)
open('$WWW/upload.bin','wb').write(bytes(random.getrandbits(8) for _ in range(300000)))"
want=$(md5sum < $WWW/upload.bin | cut -d' ' -f1)
curl -s --max-time 30 --data-binary @$WWW/upload.bin \
    http://127.0.0.1:${P61080}/api/echo > $RUNDIR/upload_echo.bin
[ "$(md5sum < $RUNDIR/upload_echo.bin | cut -d' ' -f1)" = "$want" ]
check "proxy captures a 300000-byte request body (byte-exact)" $?
rm -f $RUNDIR/upload_echo.bin

# The point of capturing rather than relaying: a client that abandons its
# upload must leave the backend with NOTHING — not a truncated request it
# cannot distinguish from a complete one, and may already have acted on.
# Asserted against the backend's own record of what reached it, and the
# control below proves that record is being written.
python3 test/upload_abort.py >/dev/null
sleep 0.5
! grep -q ' /api/abandoned ' "$SEEN"
check "abandoned upload reaches the backend not at all" $?
grep -q ' /api/echo 300000$' "$SEEN"
check "backend record control (the completed upload IS in it)" $?

# --- chunked uploads too large to buffer: captured and decoded as they
# arrive, then forwarded as an ordinary counted request. Before this they were
# a 413 outright, since only the counted path could stream. ---
for m in big head bad abort cap flood twice pipeline; do
    out=$(python3 test/upload_chunked.py $m)
    [ "$out" = "OK" ]
    case $m in
      big)   check "chunked upload captured byte-exact through ragged framing ($out)" $? ;;
      head)  check "chunked upload reaches the backend counted, not chunked ($out)" $? ;;
      bad)   check "chunked upload with a bad chunk size is 400 ($out)" $? ;;
      abort) check "abandoned chunked upload reaches the backend not at all ($out)" $? ;;
      cap)   check "chunked upload past max_body is 413, not a reset ($out)" $? ;;
      flood) check "endless chunked trailers hit max_body too ($out)" $? ;;
      twice) check "two chunked captures on one kept-alive connection ($out)" $? ;;
      pipeline) check "a GET pipelined behind a chunked upload is still served ($out)" $? ;;
    esac
done

# The rewritten upstream head goes into up_buf behind ONE up-front bound, and
# .append is an unchecked rep movsb — so a head that clears the bound but whose
# rewrite outgrows it runs off the end of the slot into the next connection.
# The bound has ~24 bytes of margin over everything the rewrite adds (Via, the
# Connection line, a Content-Length when a chunked one was dropped); this walks
# a head across the boundary in both framings and expects only 200 or 431.
if extensive; then
    out=$(python3 test/h1_upbuf_test.py ${P61080} 2>&1 | tail -1)
    [ "$out" = "OK" ]
    check "a proxied head at the up_buf boundary is served or refused ($out)" $?
else
    skip "a proxied head at the up_buf boundary -- 44s, it walks every size across the bound"
fi

# The same, counted: two captures on one connection. The bodies must DIFFER —
# with identical ones a second upload served out of the first one's file looks
# perfectly correct.
python3 -c "
import random
random.seed(31); open('$WWW/up1.bin','wb').write(bytes(random.getrandbits(8) for _ in range(200000)))
random.seed(41); open('$WWW/up2.bin','wb').write(bytes(random.getrandbits(8) for _ in range(250000)))"
curl -s --max-time 30 -o $RUNDIR/up1_echo.bin --data-binary @$WWW/up1.bin http://127.0.0.1:${P61080}/api/echo \
     --next -s --max-time 30 -o $RUNDIR/up2_echo.bin --data-binary @$WWW/up2.bin http://127.0.0.1:${P61080}/api/echo
[ "$(md5sum < $RUNDIR/up1_echo.bin | cut -d' ' -f1)" = "$(md5sum < $WWW/up1.bin | cut -d' ' -f1)" ] &&
[ "$(md5sum < $RUNDIR/up2_echo.bin | cut -d' ' -f1)" = "$(md5sum < $WWW/up2.bin | cut -d' ' -f1)" ]
check "two counted captures on one kept-alive connection" $?
rm -f $RUNDIR/up1_echo.bin $RUNDIR/up2_echo.bin $WWW/up1.bin $WWW/up2.bin

# A request pipelined in the SAME recv as a streamed body's final bytes must
# still be answered. It used to be dropped: the capture read the whole recv into
# out_buf and kept only the body, discarding the request behind it, so the
# client hung. Covers counted and chunked framing with the seam forced to the
# body's end, one byte into the next request, and mid-terminal-chunk. The
# existing "twice" checks miss it because they read the first response before
# sending the second request, so the two never share a recv.
out=$(python3 test/h1_stream_pipeline.py ${P61080} 2>&1 | tail -1)
[ "$out" = "OK" ]
check "a request pipelined behind a streamed body is served, not dropped ($out)" $?

# max_body is what stands between one client and the filesystem, so it is
# refused on the declared length — before a byte of it is written anywhere.
resp=$(raw_http "POST /api/toobig HTTP/1.1\r\nHost: one.test\r\nContent-Length: 99999999999\r\n\r\n")
check_http "upload past max_body is 413" "413 Content Too Large" "$resp"
! grep -q ' /api/toobig ' "$SEEN"
check "the refused upload never reached the backend" $?

# --- proxied request log lines: upstream status, relayed byte count ---
grep -qE 'request one\.test from 127\.0\.0\.1:[0-9]+ "GET /api/simple HTTP/1\.1" 200 12' "$LOG"
check "proxy log 200" $?
grep -qF '"POST /api/echo HTTP/1.1" 200 10' "$LOG"
check "proxy log body bytes" $?
grep -qF '"GET /api/target?x=1&y=2 HTTP/1.1" 200' "$LOG"
check "proxy log query" $?
grep -qF '"GET /down/x HTTP/1.1" 502 0' "$LOG"
check "proxy log 502" $?
grep -qF '"GET /api/slow HTTP/1.1" 504 0' "$LOG"
check "proxy log 504" $?
grep -qF '"HEAD /api/simple HTTP/1.1" 200 0' "$LOG"
check "proxy log HEAD" $?

# --- websockets: upgrade passthrough and the full-duplex tunnel ---
out=$(python3 test/ws_client.py echo)
[ "$out" = "OK" ]
check "ws echo round trips ($out)" $?
out=$(python3 test/ws_client.py pipelined)
[ "$out" = "OK" ]
check "ws client bytes before the 101 ($out)" $?
out=$(python3 test/ws_client.py push)
[ "$out" = "OK" ]
check "ws server push and 101 leftover ($out)" $?
out=$(python3 test/ws_client.py tick)
[ "$out" = "OK" ]
check "ws one-way traffic outlives idle timeout ($out)" $?
out=$(python3 test/ws_client.py silent)
[ "$out" = "OK" ]
check "ws idle tunnel times out ($out)" $?
out=$(python3 test/ws_client.py reject)
[ "$out" = "OK" ]
check "ws upgrade refusal passes through ($out)" $?
# a 101 the client never asked for must not start a tunnel
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/101)
check_http "unrequested 101 becomes 502" "502 Bad Gateway" "$resp"
# ...and nothing open may hold up a stop. These two run their own servers,
# because they stop them — 61080 is serving the rest of the suite. The second
# waits out the 30s drain deadline, and is the slowest check in the file.
# linnea-ws heartbeats its clients rather than letting the proxy reap them on
# silence. Both halves are checked, and each is the other's control: a server
# that never reaped, and one that dropped everyone, each pass exactly one of
# them. ~50s, which is the price of a real 30s ping and its 15s grace.
if extensive; then
    hb=$(timeout 120 python3 test/ws_heartbeat_test.py ${P61701} 30 15 2>&1)
    [ "$hb" = "OK" ]
    check "ws: clients that answer the ping live, silent ones are dropped ($hb)" $?
else
    # 105 s at the shipped intervals, and every second of it is waiting -- the
    # most expensive check in the file by a factor of two. So the fast suite
    # runs the SAME test against the SAME source built at 3 s / 1.5 s, on a
    # backend of its own so the other ws checks keep the shipped one (a 1.5 s
    # pong deadline would drop the tunnel clients that never answer a ping).
    # It proves what the check is for -- an answering client lives, a silent
    # one is dropped, and dropped inside its window -- and stops proving the
    # interval, which is why the full run above still pays the 105 s.
    make -s bin/linnea-ws-fast >/dev/null 2>&1
    if [ -x bin/linnea-ws-fast ]; then
        ./bin/linnea-ws-fast ${P61704} >/dev/null 2>&1 &
        wsfast_pid=$!
        for _ in $(seq 1 60); do
            (echo > /dev/tcp/127.0.0.1/${P61704}) >/dev/null 2>&1 && break
            sleep 0.1
        done
        hb=$(timeout 60 python3 test/ws_heartbeat_test.py ${P61704} 3 1.5 2>&1)
        [ "$hb" = "OK" ]
        check "ws: clients that answer the ping live, silent ones are dropped, at 3s/1.5s ($hb)" $?
        kill $wsfast_pid 2>/dev/null
        wait $wsfast_pid 2>/dev/null
    else
        check "ws heartbeat (skipped: bin/linnea-ws-fast would not build)" 1
    fi
fi

out=$(python3 test/ws_drain_test.py)
[ "$out" = "OK" ]
check "a stop is immediate whatever is open ($out)" $?
out=$(python3 test/reload_deadline_test.py)
case "$out" in OK*) true ;; *) false ;; esac
check "a reload retires an old worker a tunnel pins ($out)" $?

# --- the upload capture lands on the filesystem spill_dir names -----------
# doc_claims_test covers the parsing and validation of the key. What it cannot
# see is the two open() sites going back to a hardcoded "/tmp" — silent, and
# its only symptom is uploads held in RAM instead of on disk. An O_TMPFILE has
# no directory entry, so the descriptor in /proc is the only evidence there is.
mkdir -p test/spill
python3 test/proxy_backend.py >/dev/null 2>&1 &
spill_backend_pid=$!
backend_ready
start_server $CFG/tls-h3-big.json
P61498=$SRV_PORT
h3big_pid=$SRV_PID
sleep 0.3
start_server $CFG/spill-dir.json
P61495=$SRV_PORT
spill_pid=$SRV_PID
sleep 0.3
out=$(timeout 60 python3 test/spill_dir_test.py ${P61495} test/spill $spill_pid 2>&1)
case "$out" in ok*) true ;; *) false ;; esac
check "the upload capture file is created under spill_dir ($out)" $?
# h3 uploads whose body goes straight to the capture file, at two sizes that
# fail for two different reasons. Every OTHER h3 upload check in the suite uses
# a body under 7 KB, which keeps the whole request on the RAM path -- so none of
# them reaches this code at all, and 635/0 said nothing about the case the
# direct-to-file change was FOR.
#
# 40000 is the one that pins the bug. Inside a payload the granted ceiling is
# capped at the payload's end, and a grant smaller than RA_GRANT (16 KiB) was
# suppressed as not worth a packet -- so the last step up to that cap was never
# sent and the peer stalled a few bytes short of a body it had already declared.
# The broken band was payloads from RA_BUF (where the file path engages) up to
# where the final step reaches RA_GRANT: 34000..49000 hung every time, 33000 and
# 50000 never did. It is deterministic and answers in ~0.1s, so it is the cheap
# guard; if only this one fails, the grant floor has come back.
#
# 16000000 crosses RA_WINDOW (4 MiB) instead, where the ceiling has to keep
# following body_hi across many grants rather than being set once. It is slow
# (~8s) but it is the only check that exercises a payload longer than the window.
#
# A NOTE ON MEASURING THESE, which cost most of a day: the leftover that
# triggered the stall is just the payload end modulo how far body_hi happened to
# jump between grant evaluations, so at a size near the band edge one run hangs
# and the next does not. 8 MB completed three times and then hung on the same
# binary, and a bisect read that as a tidy "2 x RA_WINDOW" threshold that never
# existed. Sizes inside the band above are deterministic; sizes outside it are
# not evidence of anything.
# Three sizes, one per ingest path, and each one SAYS which path it took rather
# than being trusted to take it: 3000 stays in RAM (the control), 200000 opens a
# capture-file region, 16000000 opens one longer than RA_WINDOW and so is the
# only one that reaches the grant loop where the suppressed-last-step deadlock
# lived.
#
# The RAM case has now had to move three times, and the third time is the one
# worth reading. It was 40000, then 8000 when the inline buffer dropped to 16
# KiB -- both times because the number here had to follow a constant. This time
# the derivation itself was wrong: the gate stopped being the advertised window
# when a body started BORROWING its buffer, so 8000 and 200000 were BOTH on the
# RAM path and the middle case had been testing the control's path while saying
# "capture-file". h3_upload_big.py now reads the gate out of the header, and
# 3000 is under it (LINNEA_QUIC_RA_REGION_MIN, 4096).
for spec in "3000 ram" "200000 file" "16000000 file"; do
    set -- $spec
    out2=$(timeout 120 python3 test/quic/h3_upload_big.py localhost $1 ${P61498} --path $2 2>&1)
    case "$out2" in ok*) true ;; *) false ;; esac
    check "h3 upload of $1 bytes echoes back byte-exact ($out2)" $?
done
# A stream ENDED at exactly the flow-control limit, in an empty frame of its
# own, while a gap remains in the payload. Inside a payload the limit we grant
# IS the payload's end, and the reassembly base stays pinned at its start, so
# that offset looked a whole payload past a 32 KiB window: the connection was
# closed with FLOW_CONTROL_ERROR against a peer that had done nothing wrong.
# The check also sends 64 bytes PAST the end, which must STILL be refused --
# without that half it would pass just as well against a server that stopped
# checking the bound at all.
out3=$(timeout 120 python3 test/quic/h3_fin_at_limit_test.py ${P61498} 2>&1)
case "$out3" in ok*) true ;; *) false ;; esac
check "h3 a stream ended at the flow-control limit is not a violation ($out3)" $?
# An upload in progress survives other connections ending. A teardown releases
# all RA_CTXS contexts and closes any descriptor they hold, but "holds one" was
# spelled != -1 while a freshly allocated connection slot is ZEROED -- so every
# connection that ended closed fd 0 once per unused context, and fd 0 is
# routinely another request's capture file (the worker closes stdin). That
# upload then died with a 413 naming no method and no path.
out4=$(timeout 120 python3 test/quic/h3_capture_fd_test.py ${P61498} 2>&1)
case "$out4" in ok*) true ;; *) false ;; esac
check "h3 an upload survives other connections being torn down ($out4)" $?
# A body split across several DATA frames, where a non-final one is big enough
# to take the capture-file path. Closing a payload region leaves through the
# done-check with nothing to feed, and the grant lived only on the feed's tail
# -- so the peer was left holding a ceiling equal to the base, with no credit
# for the next frame's header, and both sides waited for ever. Every other h3
# upload check sends ONE DATA frame, which is what hid it.
out5=$(timeout 120 python3 test/quic/h3_multi_data_test.py ${P61498} 2>&1)
case "$out5" in ok*) true ;; *) false ;; esac
check "h3 a body in several DATA frames keeps its credit ($out5)" $?
# Several uploads at once on ONE connection. Every other upload check runs one
# request at a time, so nothing asked what happens when the RA_CTXS (6)
# reassembly contexts are all in use -- which a browser posting several files
# does immediately. Six must be served byte-exact (the bodies differ in length,
# so a reassembly landing in the wrong context cannot pass), and past six the
# rest must be REFUSED with H3_REQUEST_REJECTED rather than dropped: that is
# what makes a limit of six acceptable, because the client is told it may
# retry. A stream ending in NEITHER a response nor a reset is the regression.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    # The LAST packet of an exchange can only be recovered by the probe timer:
    # tx_detect_loss needs LINNEA_QUIC_LOSS_THRESH later packets acknowledged and
    # there are none after the last one. So the timer's value IS the tail latency,
    # and it was the 1022 ms kInitialRtt guess on every connection because no RTT
    # sample was ever taken -- the largest acknowledged packet is usually one of
    # our own bare ACKs, which were emitted with no send time recorded, so the
    # lookup missed and the sample was discarded. Measured 1035 ms before, 33 ms
    # after. The bound is generous: anything near a second means the sampling has
    # stopped working again, whatever the box is doing.
    # A browser-shaped upload: several LARGE DATA frames, which is what a Chrome
    # netlog showed (three of 371,712 bytes for 1 MB). The stall lives at the
    # frame BOUNDARY -- inside a payload the ceiling runs ahead of what has
    # landed, so every other upload check here is single-frame and blind to it.
    # Chrome blocked five times on it, for ~390 ms of a 3.1 s upload.
    #
    # WHAT IS ASSERTED IS WHERE THE CEILING STOPS, not a time: no grant may land
    # on a payload's end, because a peer holding one of those cannot start the
    # next frame until this one is whole and a further grant has come back. That
    # is exact and needs no round trip, which matters because loopback grants
    # instantly and no timing bound here separates the builds (the test's own
    # header records the measurements that showed it, and why).
    out10=$(timeout 180 python3 test/quic/h3_upload_frames.py localhost ${P61498} 3 371712 --max-blocked 0 --rtt-ms 20 2>&1)
    check "h3 a browser-shaped multi-frame upload is invited past every frame ($out10)" $?
    # ...and the same shape driven at ~19 MB/s, which is what it takes to make a
    # boundary cost anything on loopback: the congestion window and the pacer
    # both lifted, so the server's window is the only brake and every boundary
    # is crossed by a STREAM frame straddling the payload's end. That split is
    # the new code; this is what runs it at rate.
    out11=$(timeout 180 python3 test/quic/h3_upload_frames.py localhost ${P61498} 10 400000 --max-blocked 0 --rtt-ms 40 --fast-client 2>&1)
    check "h3 ...and the same at 19 MB/s, every boundary a straddling frame ($out11)" $?
    # THE OTHER BROWSER'S SHAPE, and the one every other upload check here misses:
    # frames SMALLER than the advertised window. Firefox frames a body that way
    # and Chrome does not, so a rule keyed on a frame's size treats them
    # differently -- which is exactly how a build that gave Chrome 2.9 MB/s and
    # Firefox 440 kB/s on the same 40 MB file passed this suite 693/0.
    #
    # What it asserts is the window the peer ends up with, not a time: the server
    # lends a big buffer for the duration of a body and grants half of whatever
    # buffer a stream holds, so a ceiling step wider than the advertised window
    # is proof the lend happened. Measured 525344 against 8945 on the build that
    # shipped the fault.
    #
    # --max-grants rides along on the same run because this is the framing that
    # provokes it: 500 frames of 8 KiB each open a capture-file region, and a
    # region fires the "last step up to the cap" grant on its first evaluation.
    # Measured on this exact check: 500 grants against 8, and the widest ceiling
    # STEP falls from 524480 to 8195 with it -- so the peer is re-granted a
    # frame at a time, and the borrow assertion above reads that as no buffer
    # having been lent at all. The bound of 150 sits between the two.
    out12=$(timeout 180 python3 test/quic/h3_upload_frames.py localhost ${P61498} 500 8192 --rtt-ms 20 --expect-borrow --max-grants 150 2>&1)
    check "h3 a body framed SMALL still gets a real window, and not a grant per frame ($out12)" $?
    out8=$(timeout 120 python3 test/quic/h3_tail_loss.py localhost ${P61498} /api/simple --drop 1 --max-ms 400 2>&1)
    check "h3 a lost final response is recovered from a MEASURED rtt ($out8)" $?
    out9=$(timeout 120 python3 test/quic/h3_tail_loss.py localhost ${P61498} /api/simple --drop 0 --max-ms 400 2>&1)
    check "h3 ...and the same exchange with nothing dropped ($out9)" $?
    out7=$(timeout 200 python3 test/quic/h3_concurrent_uploads_test.py ${P61498} 2>&1 | tail -1)
    case "$out7" in ok*) true ;; *) false ;; esac
    check "h3 six concurrent uploads on one connection ($out7)" $?
else
    check "h3 concurrent uploads (skipped: aioquic/pylsqpack unavailable)" 0
fi
# A peer that says it is blocked must be told the window again. MAX_DATA rides
# whatever 1-RTT packet is going out, and for an uploading peer that is usually
# a bare ACK -- which this server emits UNTRACKED, so a lost one is never
# retransmitted, and the next grant only fires when more data arrives, which is
# what a blocked peer cannot send. DATA_BLOCKED is the peer's own remedy under
# RFC 9000 4.1 and was parsed only to be stepped over.
if python3 -c 'import aioquic' 2>/dev/null; then
    outb=$(timeout 90 python3 test/quic/h3_data_blocked_test.py ${P61498} 2>&1)
    case "$outb" in ok*) true ;; *) false ;; esac
    check "h3 DATA_BLOCKED re-advertises the connection window ($outb)" $?
else
    check "h3 DATA_BLOCKED (skipped: aioquic unavailable)" 0
fi
# A body the server CANNOT CAPTURE must not be reported as one the client sent
# too much of. Opening the capture file, writing it, a full filesystem and a
# payload fragmented past the range list all returned a bare -1, and the caller
# turned every -1 into the same verdict as a body past max_body: 413. The
# access line carries no method and no path (the head never parsed), so a
# failed write and an oversized upload were indistinguishable in the log too --
# which is how a capture file closed by another connection went unattributed.
# The check walks 200 -> 413 -> 500 -> 200, the last so that a server which
# answered 500 for ever afterwards could not pass it.
mkdir -p test/spill_fail
start_server $CFG/tls-h3-spillfail.json
P61492=$SRV_PORT
h3sf_pid=$SRV_PID
sleep 0.3
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    out6=$(timeout 200 python3 test/quic/h3_capture_fail_test.py ${P61492} test/spill_fail 2>&1)
    case "$out6" in ok*|skipped*) true ;; *) false ;; esac
    check "h3 an uncapturable body is a 500, not the client's fault ($out6)" $?
else
    check "h3 uncapturable body (skipped: aioquic/pylsqpack unavailable)" 0
fi
kill $h3sf_pid 2>/dev/null
wait $h3sf_pid 2>/dev/null
chmod 755 test/spill_fail 2>/dev/null
kill $spill_pid $h3big_pid $spill_backend_pid 2>/dev/null
wait $spill_pid 2>/dev/null
wait $spill_backend_pid 2>/dev/null

# --- the assembly websocket backend, direct and through the tunnel ---
# The same battery both ways: RFC 6455 handshake, framing, unmasking, the
# broadcast, and the protocol errors. Passing directly but failing proxied
# would put the fault in linnea's tunnel rather than in the backend.
# The /api backend, which had no coverage at all until a read of it turned up
# five faults — including one that stopped the whole server indefinitely. It is
# spoken to directly: linnea's side of /api is exercised by the proxy tests.
./bin/linnea-api ${P61703} >/dev/null 2>&1 &
api_pid=$!
for _ in $(seq 1 60); do
    (echo > /dev/tcp/127.0.0.1/${P61703}) >/dev/null 2>&1 && break
    sleep 0.1
done
if extensive; then
    api_out=$(python3 test/api/api_backend_test.py ${P61703} 2>&1)
    [ $? -eq 0 ]
    check "the /api backend" $?
    # Inside the guard, because it READS what the guard assigns. Left outside it
    # this line met `set -u` on a fast run, and the shell it died in was the one
    # holding the rest of the block: five later checks failed against a server
    # that was no longer there. A skipped check is a variable that was never
    # set, which is the same hazard as a skipped fixture wearing different
    # clothes.
    printf '%s\n' "$api_out" | grep -q "^FAIL" && printf '%s\n' "$api_out" | sed -n 's/^FAIL /  api: /p'
else
    skip "the /api backend -- 10s"
fi
kill $api_pid 2>/dev/null

ws_direct_out=$(python3 test/api/ws_backend_test.py ${P61701} 2>&1)
[ $? -eq 0 ]
check "websocket backend, spoken to directly" $?
ws_proxy_out=$(python3 test/api/ws_backend_test.py ${P61080} /ws 2>&1)
[ $? -eq 0 ]
check "websocket backend, through linnea's tunnel" $?
for out in "$ws_direct_out" "$ws_proxy_out"; do
    printf '%s\n' "$out" | grep -q "^FAIL" && printf '%s\n' "$out" | sed -n 's/^FAIL /  ws: /p'
done
# an upgrade wish on a static location changes nothing
resp=$(curl -si --max-time 3 -H 'Connection: upgrade' -H 'Upgrade: websocket' \
    http://127.0.0.1:${P61080}/hello.txt)
check_http "upgrade on static location" "hello from linnea" "$resp"
grep -qF '"GET /api/ws-echo HTTP/1.1" 101 0' "$LOG"
check "ws request log 101" $?
grep -qF ': upstream closed' "$LOG"
check "ws termination upstream closed" $?

# --- send timeout: a client that stops reading must not pin its slot ---
# huge.bin is sparse and far larger than any kernel socket buffering, so
# once the client's window fills the send stalls and its linked timeout
# (2s in this config) fires.
truncate -s 64M $WWW/huge.bin
(exec 3<>/dev/tcp/127.0.0.1/${P61080}
 printf 'GET /huge.bin HTTP/1.1\r\nHost: one.test\r\n\r\n' >&3
 sleep 6) &
stall_pid=$!
sleep 4
grep -qF ': send timeout' "$LOG"
check "termination send timeout" $?
kill $stall_pid 2>/dev/null
wait $stall_pid 2>/dev/null
# a slow but reading client must survive a transfer spanning several
# timeout windows: partial sends re-arm with a fresh timeout each time
n=$(curl -s --max-time 12 --limit-rate 16M http://127.0.0.1:${P61080}/huge.bin | wc -c)
[ "$n" -eq 67108864 ]
check "slow reader outlives send timeout ($n bytes)" $?
# ...and a client that RESETS mid-response is not an error at all. ECONNRESET
# and EPIPE on the sending side are what a closed tab looks like from this end;
# the receive side learned that in 911e0b9 while the send side filed all of it
# as "send error", 49 times in the production log with no errno to say which
# write failed. huge.bin is still here and is larger than any socket buffer, so
# a client that reads one byte and then closes with SO_LINGER 0 leaves a send in
# flight for the RST to break. Verified against 8d67ffd~1, which calls the same
# scenario "send error".
out8=$(timeout 60 python3 test/send_reset_test.py ${P61080} "$LOG" "peer reset" plain 2>&1)
case "$out8" in ok*) true ;; *) false ;; esac
check "a reset mid-response is peer reset, not a send error ($out8)" $?

# --- connection termination log lines ---
grep -qF ': close after response' "$LOG"
check "termination close-after-response" $?
grep -qF ': peer closed' "$LOG"
check "termination peer closed" $?
# A client that hangs up abruptly (RST) is ECONNRESET, which is what a browser
# closing a tab looks like — routine, and told apart from a real read failure
# rather than logged as "recv error" with the errno thrown away.
python3 - <<'RST'
import os, socket, struct, time
_PB = int(os.environ.get("LINNEA_TEST_PORT_BASE", 61000))
s = socket.create_connection(("127.0.0.1", _PB + 80), timeout=5)
s.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: one.test\r\n")   # unfinished
s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
s.close()
time.sleep(0.6)
RST
grep -qF ': peer reset' "$LOG"
check "termination peer reset (RST is not an error)" $?
! grep -qF 'recv failed, errno 104' "$LOG"
check "a reset does not log an errno line" $?
grep -qF ': idle timeout' "$LOG"
check "termination idle timeout" $?

