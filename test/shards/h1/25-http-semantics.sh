# HTTP/1 semantics: ranges, vhosts, percent-decoding, path normalization, request bodies, protocol errors, MIME, methods, Host rules, request log, keep-alive, pipelining, idle timeout.

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
# A position too big for 64 bits must not wrap. The accumulator saturated at
# 2^62 but the check ran AFTER the multiply, so 2^62 * 10 wrapped back under
# the limit and 18446744073709551616 (2^64) read as 0: an out-of-range start
# served byte zero as a 206 (audit 131). The digit below the wrap, 2^64-1, is
# the control that says the 416s below are not "every long number is refused":
# it took the same path before the fix and already answered 416.
U64=18446744073709551616
resp=$(curl -si --max-time 2 -H "Range: bytes=$U64-" http://127.0.0.1:${P61080}/hello.txt)
check_http "overflow first 416"  "416 Range Not Satisfiable" "$resp"
resp=$(curl -si --max-time 2 -H 'Range: bytes=18446744073709551615-' http://127.0.0.1:${P61080}/hello.txt)
check_http "2^64-1 first 416"    "416 Range Not Satisfiable" "$resp"
resp=$(curl -si --max-time 2 -H 'Range: bytes=99999999999999999999999999999999-' http://127.0.0.1:${P61080}/hello.txt)
check_http "32-digit first 416"  "416 Range Not Satisfiable" "$resp"
# saturation is sticky, so an oversized last still means "to the end" -- the
# same answer bytes=6-9999 gets above, not a one-byte slice and not a 416
resp=$(curl -si --max-time 2 -H "Range: bytes=0-$U64" http://127.0.0.1:${P61080}/hello.txt)
check_http "overflow last 206"   "206 Partial Content" "$resp"
check_http "overflow last to EOF" "Content-Range: bytes 0-17/18" "$resp"
resp=$(curl -si --max-time 2 -H "Range: bytes=-$U64" http://127.0.0.1:${P61080}/hello.txt)
check_http "overflow suffix all" "Content-Range: bytes 0-17/18" "$resp"
# and an oversized first with a smaller last is first > last: ignored, a 200,
# exactly as bytes=5-2 is -- the huge number gets no special treatment
resp=$(curl -si --max-time 2 -H "Range: bytes=$U64-0" http://127.0.0.1:${P61080}/hello.txt)
check_http "overflow backwards 200" "200 OK" "$resp"
check_http "overflow backwards full" "Content-Length: 18" "$resp"
# the acceptance control: an ordinary range still slices, so none of the above
# is satisfied by a build that refused or ignored every Range field
resp=$(curl -si --max-time 2 -H 'Range: bytes=2-5' http://127.0.0.1:${P61080}/hello.txt)
check_http "plain range still 206" "Content-Range: bytes 2-5/18" "$resp"
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

# --- field-value bytes (audit-report-121) ---

# RFC 9110 5.5: field-vchar is VCHAR (0x21-0x7e) or obs-text (0x80-0xff), so DEL
# is not legal in a field value. The RFC lets a recipient keep an invalid CTL
# only "within a safe context ... not processed by any downstream HTTP parser",
# which a proxy is the opposite of: it was reaching the backend verbatim, so
# linnea and the backend could disagree about whether the request was valid.
# Checked on a PROXY route for that reason, not a static one.
check_http "DEL in a field value is refused" "400 Bad Request" \
    "$(raw_http 'GET /api/simple HTTP/1.1\r\nHost: one.test\r\nX-Test: before\x7fafter\r\nConnection: close\r\n\r\n')"
# ACCEPTANCE CONTROL. Without it a parser that refused every field value -- or
# every request -- would pass the check above. Same route, same header, one
# byte different.
check_http "...and the same header without it still passes" "200 OK" \
    "$(raw_http 'GET /api/simple HTTP/1.1\r\nHost: one.test\r\nX-Test: before-after\r\nConnection: close\r\n\r\n')"
# The two bytes on either side of the hole stay legal: 0x7e closes VCHAR and
# 0x80 opens obs-text, so a fix that clamped at "anything above 0x7e" would
# refuse obs-text the grammar allows and this control would catch it.
check_http "...and 0x7e and 0x80 around it are still legal" "200 OK" \
    "$(raw_http 'GET /api/simple HTTP/1.1\r\nHost: one.test\r\nX-Test: a\x7eb\x80c\r\nConnection: close\r\n\r\n')"

# --- path normalization (raw, curl normalizes dot segments itself) ---
check_http "double slash"   "hello from linnea" "$(raw_http 'GET //hello.txt HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "dot segment"    "hello from linnea" "$(raw_http 'GET /./hello.txt HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "dotdot resolve" "hello from linnea" "$(raw_http 'GET /sub/../hello.txt HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "dotdot to dir"  "linnea index page" "$(raw_http 'GET /sub/.. HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "above root"     "400 Bad Request" "$(raw_http 'GET /a/../../x HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"

# --- request bodies ---
# A static location does not accept request content (RFC 9110 9.3.1): it never
# reads it, so serving the file regardless discards bytes the client announced,
# which is the smuggling shape 9.3.1 names. This check used to assert the
# opposite -- the body was discarded and the connection kept alive, so the
# request pipelined behind it came back as a SECOND 200 -- and h1 refused only
# the half it happened to notice, a body too big to sit in in_buf. The
# expectation moves with the behaviour, the way the chunked one below already
# had to. The script also covers the other half: a request that stops short is
# now answered 408 instead of being dropped in silence, and an idle keep-alive
# connection is still owed that silence.
timeout 60 python3 test/h1_static_body.py ${P61080} >/dev/null 2>&1
check "static locations take no request content; a short one gets 408" $?
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
# RFC 9110 4.2.1 makes the path OPTIONAL, so authority + query with no path at
# all is a valid absolute URI. The authority scan ended only at "/", so the
# query was read as part of the authority, which the authority validator then
# refused: 400 for a request that must be served (audit-report-76). Here the
# route is a plain static one -- the query is not used to select the file, but
# it must not stop the file being served either.
resp=$(raw_http 'GET http://one.test/hello.txt?x=1 HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: absolute-form with a path and a query" "hello from linnea" "$resp"
resp=$(raw_http 'GET http://one.test?x=1 HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: absolute-form with an empty path and a query" "200 OK" "$resp"
# three.test has its own root, so WHICH index comes back says which authority
# was used -- "sub index" is three.test's, and one.test's is a full document
resp=$(raw_http 'GET http://three.test?x=1 HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: an empty path with a query still routes by authority" "sub index" "$resp"
# ...and a slash inside query DATA is not a path delimiter: were it read as one,
# the authority would end at "three.test?next=" and routing would fail
resp=$(raw_http 'GET http://three.test?next=/hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: a slash inside the query is not a path delimiter" "sub index" "$resp"
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

# authority-form (RFC 9112 3.2.3), the fourth target form and CONNECT's only
# one. It has no leading "/", so it reached the path normalizer and came back
# 400: a legal CONNECT was told its syntax was wrong, when the truth is that
# this build implements no tunnel (audit-report-125). nginx 1.30.4, asked the
# same lines, answers 405 -- so does h2 here, since report 124. The ACCEPTANCE
# half matters as much as the rejections: a build that blanket-400s CONNECT
# passes every "is 400" line below on its own.
resp=$(raw_http 'CONNECT one.test:443 HTTP/1.1\r\nHost: one.test:443\r\n\r\n')
check_http "target: authority-form CONNECT is 405, not 400" "405 Method Not Allowed" "$resp"
check_http "target: the CONNECT 405 carries Allow" "Allow: GET, HEAD" "$resp"
resp=$(raw_http 'CONNECT [::1]:443 HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: a bracketed IPv6 authority-form CONNECT is 405" "405 Method Not Allowed" "$resp"
resp=$(raw_http 'CONNECT one.test:65535 HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: the top port is accepted authority-form" "405 Method Not Allowed" "$resp"
# ...and the rejections, all of them the shared authority grammar's, not a
# second one written for CONNECT
resp=$(raw_http 'CONNECT bad/path HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: CONNECT with a path in the authority is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'CONNECT user@host:443 HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: CONNECT with userinfo is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'CONNECT one.test:99999 HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: CONNECT with an out-of-range port is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'CONNECT one.test:44a HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: CONNECT with a non-numeric port is 400" "400 Bad Request" "$resp"
# CONNECT names a host AND a port: it has no scheme to take a default from
# (RFC 9110 9.3.6), so a bare host names no destination. Same rule as h2's.
resp=$(raw_http 'CONNECT one.test HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: CONNECT without a port is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'CONNECT [::1] HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: a bracketed CONNECT without a port is 400" "400 Bad Request" "$resp"
# report 126: the IP-literal grammar's other alternative, IPvFuture, was
# refused here too -- so a legal CONNECT target was told its syntax was wrong.
# nginx 1.30.4 answers the same three lines 405, 405, 405 (it validates nothing
# inside the brackets); we answer 405 for the well-formed one and keep 400 for
# the two that are not IPvFuture at all.
resp=$(raw_http 'CONNECT [v1.fe80]:443 HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: an IPvFuture authority-form CONNECT is 405" "405 Method Not Allowed" "$resp"
resp=$(raw_http 'CONNECT [V9.x]:80 HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: an upper-case IPvFuture version flag is 405" "405 Method Not Allowed" "$resp"
resp=$(raw_http 'CONNECT [v.fe80]:443 HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: CONNECT to an empty-version IPvFuture is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'CONNECT [v1.]:443 HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: CONNECT to an empty-value IPvFuture is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'CONNECT [v1.fe80] HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: an IPvFuture CONNECT without a port is 400" "400 Bad Request" "$resp"
# report 127: reg-name's pct-encoded alternative, missing here too -- so a
# legal "CONNECT alpha%2Etest:443" was told its syntax was wrong. The escape is
# still exactly "%" HEXDIG HEXDIG, so the malformed spelling keeps its 400 and
# the two answers stay distinguishable, which is the whole complaint.
resp=$(raw_http 'CONNECT alpha%2Etest:443 HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: a pct-encoded CONNECT authority is 405" "405 Method Not Allowed" "$resp"
resp=$(raw_http 'CONNECT alpha%ZZ.test:443 HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: a bad pct-escape in a CONNECT authority is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'CONNECT alpha%2:443 HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: a truncated pct-escape in a CONNECT authority is 400" "400 Bad Request" "$resp"
# the other three target forms are not open to CONNECT, and were the shape that
# used to reach a 405 by matching a location
resp=$(raw_http 'CONNECT /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: origin-form CONNECT is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'CONNECT http://one.test/hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: absolute-form CONNECT is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'CONNECT * HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: asterisk-form CONNECT is 400" "400 Bad Request" "$resp"
# authority-form is CONNECT's alone: no other method may send one, or a build
# that recognised "host:port" for everything would pass the lines above
resp=$(raw_http 'GET one.test:443 HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: authority-form on GET is still 400" "400 Bad Request" "$resp"
resp=$(raw_http 'POST one.test:443 HTTP/1.1\r\nHost: one.test\r\nContent-Length: 0\r\n\r\n')
check_http "target: authority-form on POST is still 400" "400 Bad Request" "$resp"
# the 405 is decided after the rest of the head, so a CONNECT that also breaks
# a Host or framing rule still gets the code naming its actual fault
resp=$(raw_http 'CONNECT one.test:443 HTTP/1.1\r\n\r\n')
check_http "target: CONNECT without a Host is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'CONNECT one.test:443 HTTP/1.1\r\nHost: one.test\r\nHost: evil.test\r\n\r\n')
check_http "target: CONNECT with two Hosts is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'CONNECT one.test:443 HTTP/1.1\r\nHost: one.test\r\nTransfer-Encoding: gzip\r\n\r\n')
check_http "target: CONNECT with an unimplemented coding is 501" "501 Not Implemented" "$resp"
resp=$(raw_http 'CONNECT one.test:443 HTTP/9.9\r\nHost: one.test\r\n\r\n')
check_http "target: CONNECT on an unsupported version is 505" "505 HTTP Version Not Supported" "$resp"

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

# ...and the version in that line is the one the client sent, not a constant.
# Every check above uses curl, which speaks 1.1, so all of them passed while
# the log wrote " HTTP/1.1" for a 1.0 request and for the HTTP/2 preface it
# answers 505 -- `"PRI * HTTP/1.1" 505` being a line this server cannot
# produce, since that literal request is a 400.
out=$(timeout 30 python3 test/h1_log_version.py ${P61080} 2>&1 | tail -1)
[ "$out" = "OK" ]
check "log version: the requests themselves are answered as expected ($out)" $?
grep -qF '"GET /hello.txt HTTP/1.0" 200' "$LOG"
check "log version: 1.0 is logged as 1.0" $?
grep -qF '"GET /hello.txt HTTP/1.2" 200' "$LOG"
check "log version: 1.2 is logged as 1.2, not as the 1.1 it is treated as" $?
grep -qF '"PRI * HTTP/2.0" 505' "$LOG"
check "log version: the HTTP/2 preface is logged as what it was" $?
grep -qF '"GET /hello.txt HTTP/3.0" 505' "$LOG"
check "log version: an unimplemented major version survives into the log" $?
grep -qF '"GET /api/simple HTTP/1.0" 200' "$LOG"
check "log version: the proxy's own log line carries it too" $?

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

