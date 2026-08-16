# HTTP/1 serving: log line, bind conflict, static files, redirects, routing, caching, pre-compressed variants.

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

