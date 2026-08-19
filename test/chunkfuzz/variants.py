"""The chunked-body grammar of RFC 9112 7.1, sliced one rule at a time.

Each entry is (name, body_bytes, verdict) where verdict is:
    "ok"  -- a VALID chunked body; every protocol must serve it, body "body"
    "bad" -- malformed; h2 and h3 must not deliver it as a clean complete 200

All three are asserted. h1 relays a chunked body byte for byte and has already
sent its head, so it cannot answer 502 once the body is under way -- but it
decodes what it forwards, so a malformed chunk is a 502 when it arrives with the
head and a closed, unterminated message when it arrives later. Neither is a
clean 200, which is what "bad" means here (audit-report-24).
"""
OK, BAD = "ok", "bad"

V = []
def v(name, body, verdict):
    V.append((name, body, verdict))

# ---- the canonical body, and shapes that are merely unusual but LEGAL -------
v("plain",              b"4\r\nbody\r\n0\r\n\r\n", OK)
v("size-uppercase-hex", b"4\r\nbody\r\n0\r\n\r\n".replace(b"4\r\n", b"4\r\n", 1), OK)
v("size-hex-af",        b"a\r\nbodybody!!\r\n0\r\n\r\n", OK)
v("size-hex-AF-upper",  b"A\r\nbodybody!!\r\n0\r\n\r\n", OK)
v("size-leading-zeros", b"004\r\nbody\r\n0\r\n\r\n", OK)
v("last-chunk-00",      b"4\r\nbody\r\n00\r\n\r\n", OK)
v("two-chunks",         b"2\r\nbo\r\n2\r\ndy\r\n0\r\n\r\n", OK)
v("ext-valid",          b"4;a=b\r\nbody\r\n0\r\n\r\n", OK)
v("ext-token-only",     b"4;note\r\nbody\r\n0\r\n\r\n", OK)
v("ext-on-last-chunk",  b"4\r\nbody\r\n0;a=b\r\n\r\n", OK)
v("trailer-valid",      b"4\r\nbody\r\n0\r\nX-T: a\r\n\r\n", OK)
v("trailer-two",        b"4\r\nbody\r\n0\r\nX-A: 1\r\nX-B: 2\r\n\r\n", OK)
v("trailer-htab-value", b"4\r\nbody\r\n0\r\nX-T: \ta b\r\n\r\n", OK)
v("trailer-empty-value",b"4\r\nbody\r\n0\r\nX-T:\r\n\r\n", OK)

# ---- chunk-size ------------------------------------------------------------
v("size-leading-sp",    b" 4\r\nbody\r\n0\r\n\r\n", BAD)
v("size-trailing-sp",   b"4 \r\nbody\r\n0\r\n\r\n", BAD)
v("size-empty",         b"\r\nbody\r\n0\r\n\r\n", BAD)
v("size-nonhex",        b"4g\r\nbody\r\n0\r\n\r\n", BAD)
v("size-plus",          b"+4\r\nbody\r\n0\r\n\r\n", BAD)
v("size-17-digit",      b"10000000000000000\r\n", BAD)
v("size-16-digit-huge", b"1fffffffffffffff\r\n", BAD)
v("size-lf-only",       b"4\nbody\r\n0\r\n\r\n", BAD)
v("size-cr-only",       b"4\rbody\r\n0\r\n\r\n", BAD)
v("size-nul",           b"4\x00\r\nbody\r\n0\r\n\r\n", BAD)

# ---- chunk-ext -------------------------------------------------------------
v("ext-lf",             b"4;a\nb\r\nbody\r\n0\r\n\r\n", BAD)
v("ext-nul",            b"4;a\x00b\r\nbody\r\n0\r\n\r\n", BAD)
v("ext-ctl",            b"4;a\x01b\r\nbody\r\n0\r\n\r\n", BAD)
v("ext-del",            b"4;a\x7fb\r\nbody\r\n0\r\n\r\n", BAD)
# chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] ),
# chunk-ext-name = token, chunk-ext-val = token / quoted-string. The rows above
# only ever asked which BYTES may appear; these ask what SHAPE they must make
# (audit-report-23). The valid ones are the point of the exercise: a decoder
# that simply refused every extension would pass every malformed row here.
v("ext-quoted",         b'4;a="q"\r\nbody\r\n0\r\n\r\n', OK)
v("ext-quoted-escape",  b'4;a="a\\"b"\r\nbody\r\n0\r\n\r\n', OK)
v("ext-quoted-semi",    b'4;a="x;y"\r\nbody\r\n0\r\n\r\n', OK)
v("ext-two",            b"4;a;b=c\r\nbody\r\n0\r\n\r\n", OK)
v("ext-bws-semi",       b"4 ;a=b\r\nbody\r\n0\r\n\r\n", OK)
v("ext-bws-equals",     b"4;a = b\r\nbody\r\n0\r\n\r\n", OK)
v("ext-empty",          b"4;\r\nbody\r\n0\r\n\r\n", BAD)
v("ext-no-name",        b"4;=bad\r\nbody\r\n0\r\n\r\n", BAD)
v("ext-no-value",       b"4;a=\r\nbody\r\n0\r\n\r\n", BAD)
v("ext-unterminated",   b'4;a="unterminated\r\nbody\r\n0\r\n\r\n', BAD)
v("ext-quote-in-token", b'4;a=b"c\r\nbody\r\n0\r\n\r\n', BAD)
v("ext-after-quote",    b'4;a="q"x\r\nbody\r\n0\r\n\r\n', BAD)
v("ext-space-in-name",  b"4;a b\r\nbody\r\n0\r\n\r\n", BAD)
v("ext-non-token",      b"4;a,b\r\nbody\r\n0\r\n\r\n", BAD)
v("ext-dangling-esc",   b'4;a="x\\\r\nbody\r\n0\r\n\r\n', BAD)

# ---- chunk-data and its CRLF ----------------------------------------------
v("data-short",         b"4\r\nbo\r\n0\r\n\r\n", BAD)
v("data-lf-only",       b"4\r\nbody\n0\r\n\r\n", BAD)
v("data-cr-only",       b"4\r\nbody\r0\r\n\r\n", BAD)
v("data-no-crlf",       b"4\r\nbodyX0\r\n\r\n", BAD)
v("truncated-mid-data", b"4\r\nbo", BAD)

# ---- last-chunk and the terminator ----------------------------------------
v("no-last-chunk",      b"4\r\nbody\r\n", BAD)
v("last-no-terminator", b"4\r\nbody\r\n0\r\n", BAD)
v("terminator-lf-only", b"4\r\nbody\r\n0\r\n\n", BAD)

# ---- trailer-section -------------------------------------------------------
v("trailer-no-colon",   b"4\r\nbody\r\n0\r\nNotAField\r\n\r\n", BAD)
v("trailer-bad-name",   b"4\r\nbody\r\n0\r\nBad Name: x\r\n\r\n", BAD)
v("trailer-empty-name", b"4\r\nbody\r\n0\r\n: v\r\n\r\n", BAD)
v("trailer-nul-value",  b"4\r\nbody\r\n0\r\nX-T: a\x00b\r\n\r\n", BAD)
v("trailer-ctl-value",  b"4\r\nbody\r\n0\r\nX-T: a\x01b\r\n\r\n", BAD)
v("trailer-del-value",  b"4\r\nbody\r\n0\r\nX-T: a\x7fb\r\n\r\n", BAD)
v("trailer-inline-lf",  b"4\r\nbody\r\n0\r\nX-T: a\nb\r\n\r\n", BAD)
v("trailer-obs-fold",   b"4\r\nbody\r\n0\r\nX-T: a\r\n  cont\r\n\r\n", BAD)
v("trailer-cr-only",    b"4\r\nbody\r\n0\r\nX-T: a\rmore\r\n\r\n", BAD)
v("trailer-partial",    b"4\r\nbody\r\n0\r\nX-T: a\r\n", BAD)
