# Audit Report 95

Audited at `6e3ed52` (`test: kill only our own linnea-api, not every one (audit-report-94)`), 2026-08-27.

This pass verified report 94's PID-scoped cleanup, then followed the recently
strengthened `proxy_sni` configuration contract into the TLS ClientHello
builder. Two independently observable SNI validation defects remain and are
batched here.

1. **Medium: an empty `proxy_sni` is accepted and encoded as an invalid empty
   TLS `HostName`.**
2. **Low: values that cannot be an SNI DNS hostname are accepted and sent
   unchanged.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — empty `proxy_sni` produces a malformed ClientHello

Severity: **Medium (P2, a configuration accepted by `--test` can make every backend handshake fail)**  
Confidence: **High**  
Status: **Confirmed by source trace; unfixed.**

RFC 6066 defines `HostName` as a vector of 1 through 65535 bytes; zero bytes is
not a legal encoding ([RFC 6066 §3](https://www.rfc-editor.org/rfc/rfc6066.html#section-3)).

The configuration parser checks only whether `proxy_sni` exceeds 255 bytes, so
`"proxy_sni": ""` is accepted and stored with length zero
([src/server/linnea_config_parse.asm:1320](/home/linnea/linnea/src/server/linnea_config_parse.asm:1320)). Because report 92 now requires SNI to accompany
`proxy_tls`, this value reaches the TLS client rather than being an inert option.

The ClientHello builder always emits a `server_name` extension. It writes the
configured length directly into the inner `HostName` length field and copies
that many bytes ([src/server/linnea_tls_client.asm:373](/home/linnea/linnea/src/server/linnea_tls_client.asm:373)). With a zero-length configuration, the wire
message therefore contains one `host_name` entry whose name vector is empty.

### Reproduction

Use a valid TLS backend location with a valid pin and `"proxy_sni": ""`.
`bin/linnea --test` accepts the configuration. Capture the resulting
ClientHello or inspect the builder output: extension type 0 contains a
`host_name` entry with length 0. A strict backend can reject the malformed
extension, turning every request to that location into a failed upstream
handshake.

### Recommended fix

Reject an explicitly configured empty `proxy_sni` during parsing with a
specific diagnostic. Add negative configuration coverage and a ClientHello
encoding test. If an absent SNI is meant to be supported, represent absence by
omitting the key and make the builder omit the entire extension when the stored
length is zero.

## Finding 2 — `proxy_sni` accepts values forbidden for `HostName`

Severity: **Low (P3, accepted configurations send non-conformant or unusable SNI values)**  
Confidence: **High**  
Status: **Confirmed by source trace; unfixed.**

RFC 6066 specifies that SNI `HostName` contains a fully qualified DNS hostname
encoded as ASCII without a trailing dot; literal IPv4 and IPv6 addresses are
not permitted ([RFC 6066 §3](https://www.rfc-editor.org/rfc/rfc6066.html#section-3)).

The parser applies only the 255-byte upper bound. Its generic string parser
accepts any non-control byte other than its globally unsupported escape syntax,
so values such as `"api.internal."`, `"127.0.0.1"`, a string containing spaces,
or raw non-ASCII UTF-8 all pass `--test`. The TLS builder copies those bytes
unchanged into `HostName`; it performs no later validation or A-label
conversion.

### Impact

Backends can reject the ClientHello, ignore the name and select a default
virtual host, or behave differently from an operator's expectation. The SPKI
pin is still checked, so this is not an authentication bypass, but it converts
invalid configuration into request-time 502 failures or surprising routing
instead of a startup diagnostic.

### Recommended fix

Validate `proxy_sni` as a non-empty ASCII DNS hostname at configuration time:
reject a trailing dot, IP literals, whitespace/non-ASCII bytes, empty labels,
and labels or totals outside DNS limits. Require callers to supply an A-label
for internationalized names, matching RFC 6066. Add acceptance controls for
ordinary names and rejection cases for each prohibited class.

---

## Resolution (2026-08-27)

**Both findings CONFIRMED and FIXED.** Fast suite **1179/0**; 16 new
`doc_claims_test.py` rows.

### F1 is WIDER than reported, and less severe than reported

The report scopes it to an explicitly configured empty `proxy_sni`. Capturing
the actual ClientHello shows **omitting `proxy_sni` entirely produces the same
zero-length HostName**:

    proxy_sni: ""       -> server_name PRESENT, HostName length=0
    proxy_sni omitted   -> server_name PRESENT, HostName length=0

The builder emitted the extension unconditionally, so this was not an opt-in
edge case: the **default** shape of a `proxy_tls` location — pin, no
`proxy_sni` — has been sending a malformed extension on every backend
handshake.

Severity, however, is lower than "can make every backend handshake fail".
Against a real OpenSSL 3.5.7 backend the handshake **completes and returns
200**. It is a conformance defect a strict peer could reject, not an outage.
Fixed because the fix is small and strictly correct, not because anything was
breaking.

Fix: omit the whole extension when `sni_len` is 0 — the extensions length is
backpatched from the cursor, so nothing else changes — and reject an explicitly
empty `proxy_sni` at parse time. Verified on the wire with a control:

    proxy_sni omitted     -> server_name extension ABSENT
    proxy_sni "localhost" -> PRESENT, HostName length=9, value=b'localhost'

This is what the report's own recommendation proposed as the alternative, and
it is the right one: absence is spelled by omitting the key.

### F2

Parse-time DNS-hostname validation per RFC 6066 3: ASCII letters/digits/hyphen
labels of 1-63, no empty or hyphen-edged label, no trailing dot, not an IP
literal. 11 rejection cases and 8 acceptance controls, with the 63/64-byte
label boundary from **both** sides. All three `proxy_sni` values already in the
tree still pass.

One correction to F2's evidence: the report lists "raw non-ASCII UTF-8" among
the values that pass `--test`. A non-ASCII value written through JSON escapes
is refused earlier, by the parser's existing "escape sequences not supported"
rule — not by any SNI check. The charset rule now covers raw bytes regardless.

### Two self-inflicted notes

The first draft of the validator contained `mov byte [rsp - 1], 0` — a write
below the stack pointer, which a signal handler can clobber. Removed. And the
first draft of the tests shadowed `doc_claims_test.py`'s own `bad` failure
accumulator with a loop variable, so its `.append` ran against a string and the
summary printed `69 FAILED: l, l, l, ...` — exactly `len("l"*64 + ".test")`.
