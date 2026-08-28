#!/usr/bin/env python3
"""Every factual claim docs/config.md makes, checked against the real binary.

A configuration reference that drifts from the parser is worse than none: the
reader trusts it. So each row of each table, each rule, and the complete
worked example are asserted here — including the example actually parsing,
which is the one thing a reader will copy verbatim.

Usage: doc_claims_test.py        (run from the repo root)
"""
import json
import os
import subprocess
import sys
import tempfile

BIN = "./bin/linnea"
D = tempfile.mkdtemp()
bad = []


def test(cfg, label, want_ok, want_msg=None):
    p = os.path.join(D, "c.json")
    open(p, "w").write(cfg if isinstance(cfg, str) else json.dumps(cfg))
    r = subprocess.run([BIN, "--test", "--config", p], capture_output=True, text=True)
    ok = (r.returncode == 0)
    err = (r.stderr or "").strip()
    good = (ok == want_ok) and (want_msg is None or want_msg in err)
    print(("PASS " if good else "FAIL ") + "%-46s %s"
          % (label, "accepted" if ok else err[:70]))
    if not good:
        bad.append(label)


def base(**over):
    c = {"log": os.path.join(D, "l.log"),
         "servers": [{"host": "127.0.0.1", "port": 61899, "hostname": "x.test",
                      "locations": [{"prefix": "/", "root": D}]}]}
    c.update(over)
    return c


def srv(**over):
    c = base()
    c["servers"][0].update(over)
    return c


def loc(l):
    c = base()
    c["servers"][0]["locations"] = l
    return c


# --- the documented example, with paths that exist here -----------------
ex = json.load(open(os.path.join(D, "..", "x"), "r")) if False else None
EXAMPLE = {
    "log": os.path.join(D, "access.log"),
    "workers": 4, "timeout": 30, "head_timeout": 10, "drain_timeout": 30,
    "max_connections": 4096, "max_per_ip": 64, "max_upstream": 256,
    "max_body": 8388608, "http2": 1,
    "servers": [
        {"host": "0.0.0.0", "port": 61897, "hostname": "example.com",
         "cert": "test/tls/server.crt", "key": "test/tls/server.key",
         "hsts": "max-age=31536000; includeSubDomains", "nosniff": 1,
         "locations": [
             {"prefix": "/api", "proxy": "127.0.0.1:8080"},
             {"prefix": "/static", "root": D,
              "cache_control": "public, max-age=604800"},
             {"prefix": "/old", "redirect": "https://example.com/new"},
             {"prefix": "/", "root": D}]},
        {"host": "0.0.0.0", "port": 61898, "hostname": "example.com",
         "locations": [
             {"prefix": "/.well-known/acme-challenge", "root": D},
             {"prefix": "/", "redirect": "https://example.com"}]}]}
test(EXAMPLE, "the documented example parses", True)

# --- the JSON dialect ----------------------------------------------------
test('{"log":"/tmp/l", /* c */ "servers":[]}', "comments rejected", False)
test('{"log":"/tmp/l","servers":[],}', "trailing comma rejected", False)
# ...including inside the multi-backend proxy array, which had its own loop and
# its own answer: `["a",]` was accepted while the same comma one line away in
# `locations` was not. A grammar that depends on which key you are under is not
# the strict subset this file documents (audit-report-40).
PROXY_ARR = ('{"log":"/tmp/l","servers":[{"host":"127.0.0.1","port":61899,'
             '"hostname":"x.test","locations":[{"prefix":"/","proxy":%s}]}]}')
test(PROXY_ARR % '["127.0.0.1:8080",]',
     "proxy array: trailing comma rejected", False)
test(PROXY_ARR % '["127.0.0.1:8080","127.0.0.1:8081",]',
     "proxy array: trailing comma after several rejected", False)
test(PROXY_ARR % '[,"127.0.0.1:8080"]',
     "proxy array: leading comma rejected", False)
test(PROXY_ARR % '["127.0.0.1:8080",,"127.0.0.1:8081"]',
     "proxy array: doubled comma rejected", False)
test(PROXY_ARR % '[]', "proxy array: empty list rejected", False,
     "names no backend")
# and the valid spellings, so the rule cannot be tightened into refusing them
test(PROXY_ARR % '["127.0.0.1:8080"]', "proxy array: one backend accepted", True)
test(PROXY_ARR % '["127.0.0.1:8080","127.0.0.1:8081"]',
     "proxy array: two backends accepted", True)
test(PROXY_ARR % '[ "127.0.0.1:8080" , "127.0.0.1:8081" ]',
     "proxy array: whitespace around the comma accepted", True)
test(PROXY_ARR % '"127.0.0.1:8080"', "proxy: the bare-string form accepted", True)

# --- unix: backends (docs/config.md `proxy`, docs/proxying.md "Backends") ----
# The length rule is asserted from BOTH sides: one value at the limit tests one
# comparison, not the boundary. sun_path is 108 including its NUL, so 107 is the
# longest storable path and 108 must be refused.
U107 = "/" + "a" * 106
U108 = "/" + "a" * 107
test(PROXY_ARR % '"unix:/run/linnea/api.sock"', "proxy: a unix: path accepted", True)
test(PROXY_ARR % '["unix:/run/a.sock","unix:/run/b.sock"]',
     "proxy array: two unix: backends accepted", True)
# The doc says an array MAY mix the two; both orders, because the parser walks
# them one at a time and a fall-through would only show up in one order.
test(PROXY_ARR % '["unix:/run/a.sock","127.0.0.1:8080"]',
     "proxy array: unix: then tcp accepted", True)
test(PROXY_ARR % '["127.0.0.1:8080","unix:/run/a.sock"]',
     "proxy array: tcp then unix: accepted", True)
test(PROXY_ARR % ('"unix:%s"' % U107), "proxy: a 107-byte unix: path accepted", True)
test(PROXY_ARR % ('"unix:%s"' % U108), "proxy: a 108-byte unix: path rejected",
     False, "path too long")
test(PROXY_ARR % '"unix:run/a.sock"', "proxy: a relative unix: path rejected",
     False, "must be absolute")
test(PROXY_ARR % '"unix:@name"', "proxy: the abstract namespace rejected",
     False, "must be absolute")
test(PROXY_ARR % '"unix:"', "proxy: unix: with no path rejected", False,
     "invalid proxy address")
# ...and the TCP form still parses, which the unix: branch broke once by being
# spliced into its fall-through.
test(PROXY_ARR % '"127.0.0.1:8080"', "proxy: tcp still accepted beside unix:", True)

# proxy_pin and proxy_tls are BOTH-OR-NEITHER. The tls->pin half was enforced
# from the start; the pin->tls half was not, and a pin without proxy_tls is not
# merely unenforced -- the connection is plaintext, so the location promised an
# authenticated backend and delivered neither authentication nor TLS. Measured
# before the fix: a deliberately WRONG pin with no proxy_tls served 200.
PIN0 = "ab" * 32
LOC = ('{"log":"/tmp/l","servers":[{"host":"127.0.0.1","port":8443,'
       '"hostname":"x.test","locations":[{"prefix":"/","proxy":"127.0.0.1:8080"'
       ',%s}]}]}')
test(LOC % ('"proxy_pin":"%s"' % PIN0), "proxy_pin without proxy_tls rejected",
     False, "would authenticate nothing")
test(LOC % '"proxy_sni":"x.test"', "proxy_sni without proxy_tls rejected",
     False, "no ClientHello")
test(LOC % ('"proxy_tls":1'), "proxy_tls without proxy_pin rejected (the half that always was)",
     False, "requires proxy_pin")
# ...and every legitimate combination still parses, so the rule cannot widen
test(LOC % ('"proxy_tls":1,"proxy_pin":"%s"' % PIN0),
     "proxy_tls + proxy_pin accepted", True)
test(LOC % ('"proxy_tls":1,"proxy_pin":"%s","proxy_sni":"x.test"' % PIN0),
     "proxy_tls + proxy_pin + proxy_sni accepted", True)
test(LOC % '"proxy_keepalive":1', "a plain proxy with keepalive still accepted", True)

# proxy_sni is a DNS hostname (RFC 6066 3), validated at parse time so a bad one
# is a startup diagnostic and not a request-time 502. The empty value mattered
# most: HostName is opaque HostName<1..2^16-1>, so zero length is not a legal
# encoding -- and the builder used to emit exactly that whenever no SNI was
# configured, which is the DEFAULT for a proxy_tls location (audit-report-95).
TLSLOC = ('{"log":"/tmp/l","servers":[{"host":"127.0.0.1","port":8443,'
          '"hostname":"x.test","locations":[{"prefix":"/","proxy":"127.0.0.1:8080"'
          ',"proxy_tls":1,"proxy_pin":"' + "ab" * 32 + '"%s}]}]}')
# NB: not `bad` -- that is this file's own failure accumulator, and shadowing it
# turns its `+=` into a character-by-character extend.
for sni_bad, why in [("", "empty"), ("127.0.0.1", "an IPv4 literal"),
                     ("api.internal.", "a trailing dot"), (".api.test", "a leading dot"),
                     ("a..b", "an empty label"), ("-x.test", "a label starting with -"),
                     ("x-.test", "a label ending with -"), ("a b.test", "a space"),
                     ("l" * 64 + ".test", "a 64-byte label")]:
    test(TLSLOC % (',"proxy_sni":"%s"' % sni_bad),
         "proxy_sni rejects %s" % why, False, "must be a DNS hostname")
# The DNS TOTAL limit, both sides. A name encodes as a length byte per label
# plus its bytes plus a root byte -- len + 2 for the textual no-trailing-dot
# form -- so RFC 1035's 255 octets puts the textual maximum at 253. Four
# 63-byte labels and three dots is 255 characters: inside the buffer, and not a
# name any resolver can represent (audit-report-96 F2).
test(TLSLOC % (',"proxy_sni":"%s"' % ".".join(["a" * 62] * 4)[:253]),
     "proxy_sni accepts 253 characters", True)
test(TLSLOC % (',"proxy_sni":"%s"' % ".".join(["a" * 62] * 5)[:254]),
     "proxy_sni rejects 254 characters", False, "must be a DNS hostname")
test(TLSLOC % (',"proxy_sni":"%s"' % ".".join(["a" * 63] * 4)),
     "proxy_sni rejects 4x63 labels (255 chars, 257 encoded)", False,
     "must be a DNS hostname")
for sni_ok in ["localhost", "api.example.com", "x1-2.test", "1a.test", "l" * 63 + ".test"]:
    test(TLSLOC % (',"proxy_sni":"%s"' % sni_ok),
         "proxy_sni accepts %s" % sni_ok[:24], True)
test(TLSLOC % "", "proxy_sni may be omitted (no server_name extension is sent)", True)

# proxy_tls (and so proxy_h2) is refused on a location naming a unix: backend:
# backend TLS is kTLS, and the TLS ULP does not exist for AF_UNIX.
PIN = "ab" * 32
UNIX_TLS = ('{"log":"/tmp/l","servers":[{"host":"127.0.0.1","port":8443,'
            '"hostname":"x.test","locations":[{"prefix":"/","proxy":"unix:/run/a.sock"'
            ',%s}]}]}')
test(UNIX_TLS % ('"proxy_tls":1,"proxy_pin":"%s"' % PIN),
     "proxy_tls with a unix: backend rejected", False, "cannot be used with a unix:")
test(UNIX_TLS % ('"proxy_tls":1,"proxy_h2":1,"proxy_pin":"%s"' % PIN),
     "proxy_h2 with a unix: backend rejected", False, "cannot be used with a unix:")
# ...and proxy_tls on a TCP backend is still fine, so the rule is not too wide.
TCP_TLS = ('{"log":"/tmp/l","servers":[{"host":"127.0.0.1","port":8443,'
           '"hostname":"x.test","locations":[{"prefix":"/","proxy":"127.0.0.1:8080"'
           ',%s}]}]}')
test(TCP_TLS % ('"proxy_tls":1,"proxy_pin":"%s"' % PIN),
     "proxy_tls with a tcp backend still accepted", True)
# --- TLS credentials: --test must not bless an unusable pair ---------------
# docs say --test "check[s] the configuration and certificates", and the hot
# upgrade runs it against the NEW binary before committing. All of these used
# to exit 0 (audit-report-99).
import os as _os
_CRT, _KEY = "test/tls/server.crt", "test/tls/server.key"
_ALT = "test/tls/sni.key"
_TD = tempfile.mkdtemp()


def _tls_cfg(cert, key):
    return json.dumps({"log": _os.path.join(_TD, "l.log"), "servers": [
        {"host": "127.0.0.1", "port": 8443, "hostname": "localhost",
         "cert": cert, "key": key,
         "locations": [{"prefix": "/", "root": "test/www"}]}]})


if _os.path.exists(_CRT):
    test(_tls_cfg(_CRT, _KEY), "a matching certificate and key are accepted", True)
    # F2: two individually valid files that are different identities
    test(_tls_cfg(_CRT, _ALT), "a certificate with an unrelated key is rejected",
         False, "different identities")
    # ...and the leaf of a MULTI-cert chain is what gets compared, not an issuer
    if _os.path.exists("test/tls/bigchain.crt"):
        test(_tls_cfg("test/tls/bigchain.crt", _KEY),
             "a multi-cert chain is paired by its LEAF", True)
    # F1: a body that decodes but is not an X.509 certificate
    _one = _os.path.join(_TD, "onebyte.crt")
    open(_one, "w").write("-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n")
    test(_tls_cfg(_one, _KEY), "a one-byte certificate body is rejected", False)
    # F3: a body whose post-encapsulation boundary is missing or truncated
    _body = open(_CRT).read().split("-----END")[0]
    _noend = _os.path.join(_TD, "noend.crt")
    open(_noend, "w").write(_body + "=\n")
    test(_tls_cfg(_noend, _KEY), "a certificate with no END boundary is rejected", False)
    _trunc = _os.path.join(_TD, "trunc.crt")
    open(_trunc, "w").write(_body + "-----END PRIVATE KEY")
    test(_tls_cfg(_trunc, _KEY), "a truncated END boundary is rejected", False)
    _kbody = open(_KEY).read().split("-----END")[0]
    _nokey = _os.path.join(_TD, "noend.key")
    open(_nokey, "w").write(_kbody + "=\n")
    test(_tls_cfg(_CRT, _nokey), "a key with no END boundary is rejected", False)

    # --- audit-report-100: the leaf must be a COMPLETE certificate, every
    # chain entry must parse, and padding is decided by the final quantum ----
    import base64 as _b64, textwrap as _tw

    def _wrap(der, path):
        body = "\n".join(_tw.wrap(_b64.b64encode(der).decode(), 64))
        open(path, "w").write(
            "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n")
        return path

    _pem = open(_CRT).read()
    _der = _b64.b64decode("".join(
        l for l in _pem.splitlines() if "-----" not in l))
    # F1: corrupt the OUTER signatureAlgorithm tag. TBSCertificate and its SPKI
    # are untouched, so a check that merely FINDS an SPKI still passes.
    if len(_der) > 327 and _der[327] == 0x30:
        _m = bytearray(_der)
        _m[327] = 0x31
        test(_tls_cfg(_wrap(bytes(_m), _os.path.join(_TD, "badleaf.crt")), _KEY),
             "a certificate with a corrupt outer field is rejected", False)
    # F2: a VALID leaf followed by a malformed issuer. The leaf pairs with the
    # key, so only per-entry validation can catch the second block -- and a
    # half-written intermediate is exactly what a renewal produces.
    _bc = _os.path.join(_TD, "badchain.crt")
    open(_bc, "w").write(
        _pem + "-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n")
    test(_tls_cfg(_bc, _KEY), "a valid leaf with a malformed issuer is rejected", False)
    # F3: padding is what the final quantum requires, not decoration
    _xp = _os.path.join(_TD, "excesspad.crt")
    open(_xp, "w").write(_pem.replace("-----END", "====\n-----END"))
    test(_tls_cfg(_xp, _KEY), "excess base64 padding is rejected", False)

    # --- audit-report-101: the field TYPES, and the declared curve ----------
    # A bounded TLV of ANY tag advances a cursor, so counting six elements
    # accepted a serialNumber retagged as an OCTET STRING. And the positional
    # SPKI walk had DROPPED the id-ecPublicKey/prime256v1 comparison that the
    # peer-key extractor always made -- a regression introduced by report 100's
    # own fix, which is why both directions are pinned here.
    if len(_der) > 145 and _der[13] == 0x02 and _der[145] == 0x07:
        _t = bytearray(_der)
        _t[13] = 0x04                      # INTEGER -> OCTET STRING
        test(_tls_cfg(_wrap(bytes(_t), _os.path.join(_TD, "badtbs.crt")), _KEY),
             "a retagged serialNumber is rejected", False)
        _c = bytearray(_der)
        _c[145] = 0x08                     # prime256v1 -> another curve OID
        test(_tls_cfg(_wrap(bytes(_c), _os.path.join(_TD, "badcurve.crt")), _KEY),
             "a certificate declaring a non-P-256 curve is rejected", False)

    # --- audit-report-102: the nested mandatory fields, not just their tags --
    # The [0] version wrapper was skipped unopened, so a Version retagged as an
    # OCTET STRING -- or holding 9 -- passed. RFC 5280 4.1.2.1: [0] EXPLICIT
    # Version, an INTEGER of v1/v2/v3.
    # Locate the [0] wrapper rather than hardcoding an offset: my first attempt
    # guarded on the wrong bytes, so BOTH of these silently did not run and the
    # suite still said "all claims hold" -- a skipped check reads as a pass.
    _vi = _der.find(b"\xa0\x03\x02\x01", 4, 20)
    if _vi < 0:
        _bad_guard = "could not locate the [0] version wrapper to mutate"
        bad.append(_bad_guard)
        print("FAIL " + _bad_guard)
    else:
        _v = bytearray(_der)
        _v[_vi + 2] = 0x04                 # INTEGER -> OCTET STRING
        test(_tls_cfg(_wrap(bytes(_v), _os.path.join(_TD, "badver.crt")), _KEY),
             "a retagged certificate version is rejected", False)
        _n = bytearray(_der)
        _n[_vi + 4] = 0x09                 # v3 -> an undefined version number
        test(_tls_cfg(_wrap(bytes(_n), _os.path.join(_TD, "badvernum.crt")), _KEY),
             "an out-of-range certificate version is rejected", False)

    # ...and the CONTROL that matters for that check: a v1 certificate omits the
    # version field entirely (DEFAULT v1), so the absent-[0] path must still
    # load. Nothing in the tree was v1, so this is built by stripping the
    # wrapper and re-encoding the lengths.
    def _mk_v1(der):
        def _tlv(b, i):
            n, j = b[i + 1], i + 2
            if n & 0x80:
                k = n & 0x7f
                n = int.from_bytes(b[j:j + k], "big")
                j += k
            return j, n

        def _len(n):
            if n < 0x80:
                return bytes([n])
            b = n.to_bytes((n.bit_length() + 7) // 8, "big")
            return bytes([0x80 | len(b)]) + b

        cs, cl = _tlv(der, 0)
        ts, tl = _tlv(der, cs)
        if der[ts] != 0xa0:
            return None
        vs, vl = _tlv(der, ts)
        tbs_c = der[vs + vl:ts + tl]
        tbs = b"\x30" + _len(len(tbs_c)) + tbs_c
        body = tbs + der[ts + tl:cs + cl]
        return b"\x30" + _len(len(body)) + body

    _v1 = _mk_v1(_der)
    if _v1:
        test(_tls_cfg(_wrap(_v1, _os.path.join(_TD, "v1.crt")), _KEY),
             "a v1 certificate (no version field) is accepted", True)

    # --- audit-report-103: AlgorithmIdentifier contents, and SPKI child count -
    # The outer signatureAlgorithm was only checked for non-emptiness, so its
    # OID could be retagged; and the SPKI's key was copied from the second child
    # without requiring it to END the sequence, so a third child went unseen.
    _oid = _der.rfind(b"\x06", 300, 340)
    if _oid < 0:
        bad.append("could not locate the outer signatureAlgorithm OID")
        print("FAIL could not locate the outer signatureAlgorithm OID")
    else:
        _a = bytearray(_der)
        _a[_oid] = 0x05                # OBJECT IDENTIFIER -> NULL
        test(_tls_cfg(_wrap(bytes(_a), _os.path.join(_TD, "badalg.crt")), _KEY),
             "a non-AlgorithmIdentifier signatureAlgorithm is rejected", False)

    def _spki_plus_null(der):
        """Re-encode the certificate with a third child inside its SPKI."""
        def _tlv(b, i):
            n, j = b[i + 1], i + 2
            if n & 0x80:
                k = n & 0x7f
                n = int.from_bytes(b[j:j + k], "big")
                j += k
            return j, n

        def _enc(tag, c):
            n = len(c)
            if n < 0x80:
                L = bytes([n])
            else:
                w = (n.bit_length() + 7) // 8
                L = bytes([0x80 | w]) + n.to_bytes(w, "big")
            return bytes([tag]) + L + c

        cs, cl = _tlv(der, 0)
        ts, tl = _tlv(der, cs)
        i = ts
        if der[i] == 0xa0:
            vs, vl = _tlv(der, i)
            i = vs + vl
        for _ in range(5):
            s2, l2 = _tlv(der, i)
            i = s2 + l2
        ss, sl = _tlv(der, i)
        spki = _enc(0x30, der[ss:ss + sl] + b"\x05\x00")
        tbs = _enc(0x30, der[ts:i] + spki + der[ss + sl:ts + tl])
        return _enc(0x30, tbs + der[ts + tl:cs + cl])

    test(_tls_cfg(_wrap(_spki_plus_null(_der), _os.path.join(_TD, "badspki.crt")),
                  _KEY),
         "an SPKI with a third child is rejected", False)

    # --- audit-report-104: ECPrivateKey is parsed to its end ----------------
    # RFC 5915 3: version, privateKey, [0] parameters OPTIONAL, [1] publicKey
    # OPTIONAL. The parser returned as soon as it had the scalar, so anything
    # after it went unexamined. Ignoring an ABSENT optional field is not the
    # same as accepting an ill-formed one.
    def _wrap_key(der, path):
        body = "\n".join(_tw.wrap(_b64.b64encode(der).decode(), 64))
        open(path, "w").write(
            "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n")
        return path

    _kder = _b64.b64decode("".join(
        l for l in open(_KEY).read().splitlines() if "-----" not in l))
    _p1 = _kder.find(b"\xa1", 60, 80)
    if _p1 < 0:
        bad.append("could not locate the [1] publicKey field in the test key")
        print("FAIL could not locate the [1] publicKey field in the test key")
    else:
        _k = bytearray(_kder)
        _k[_p1] = 0x04                    # [1] -> OCTET STRING
        test(_tls_cfg(_CRT, _wrap_key(bytes(_k), _os.path.join(_TD, "badopt.key"))),
             "a retagged [1] publicKey is rejected", False)
        _k2 = bytearray(_kder)
        _k2[_p1 + 2] = 0x04               # its inner BIT STRING -> OCTET STRING
        test(_tls_cfg(_CRT, _wrap_key(bytes(_k2), _os.path.join(_TD, "badinner.key"))),
             "a malformed [1] publicKey body is rejected", False)

        # --- audit-report-105 ------------------------------------------------
        # [0] ECParameters was skipped unopened, so a BIT STRING retagged from
        # [1] to [0] was waved through; and a well-shaped [1] was never tied to
        # the scalar, so a point that contradicts the private key passed.
        _k3 = bytearray(_kder)
        _k3[_p1] = 0xa0                   # [1] -> [0], its BIT STRING intact
        test(_tls_cfg(_CRT, _wrap_key(bytes(_k3), _os.path.join(_TD, "badparam.key"))),
             "a BIT STRING retagged as [0] parameters is rejected", False)
        _k4 = bytearray(_kder)
        _k4[_p1 + 6] ^= 0x01              # flip a bit of the embedded point
        test(_tls_cfg(_CRT, _wrap_key(bytes(_k4), _os.path.join(_TD, "badpub.key"))),
             "an embedded public key the scalar does not sign for is rejected",
             False, "does not sign for")

        # --- audit-report-110: [1] is ONE BIT STRING, not a container -------
        # The wrapper's own declared length was used to advance, so a trailing
        # TLV inside it was stepped over unseen. RFC 5915 3: publicKey [1] BIT
        # STRING OPTIONAL.
        def _pub_tail(der):
            def _tlv(b, i):
                n, j = b[i + 1], i + 2
                if n & 0x80:
                    k = n & 0x7f
                    n = int.from_bytes(b[j:j + k], "big")
                    j += k
                return j, n

            def _enc(tag, c):
                n = len(c)
                if n < 0x80:
                    L = bytes([n])
                else:
                    w = (n.bit_length() + 7) // 8
                    L = bytes([0x80 | w]) + n.to_bytes(w, "big")
                return bytes([tag]) + L + c

            ps, _ = _tlv(der, 0)
            i = ps
            vs, vl = _tlv(der, i); i = vs + vl
            as_, al = _tlv(der, i); i = as_ + al
            os_, ol = _tlv(der, i)
            ec = der[os_:os_ + ol]
            es, el = _tlv(ec, 0); j = es
            v2, l2 = _tlv(ec, j); j = v2 + l2
            k2, kl = _tlv(ec, j); j = k2 + kl
            w1, wl = _tlv(ec, j)
            inner = _enc(0x30, ec[es:j] + _enc(0xa1, ec[w1:w1 + wl] + b"\x05\x00"))
            return _enc(0x30, der[ps:as_ + al] + _enc(0x04, inner))

        test(_tls_cfg(_CRT, _wrap_key(_pub_tail(_kder),
                                      _os.path.join(_TD, "pubtail.key"))),
             "a trailing TLV inside [1] publicKey is rejected", False)

    # ...and the CONTROLS for [0], which no real key carries: PKCS#8 pins the
    # curve in the outer AlgorithmIdentifier, so generators omit the inner one.
    # Both branches are therefore reachable only from a hand-built key.
    def _with_params(der, oid):
        def _tlv(b, i):
            n, j = b[i + 1], i + 2
            if n & 0x80:
                k = n & 0x7f
                n = int.from_bytes(b[j:j + k], "big")
                j += k
            return j, n

        def _enc(tag, c):
            n = len(c)
            if n < 0x80:
                L = bytes([n])
            else:
                w = (n.bit_length() + 7) // 8
                L = bytes([0x80 | w]) + n.to_bytes(w, "big")
            return bytes([tag]) + L + c

        ps, _ = _tlv(der, 0)
        i = ps
        vs, vl = _tlv(der, i); i = vs + vl
        as_, al = _tlv(der, i); i = as_ + al
        os_, ol = _tlv(der, i)
        ec = der[os_:os_ + ol]
        es, el = _tlv(ec, 0); j = es
        v2, l2 = _tlv(ec, j); j = v2 + l2
        k2, kl = _tlv(ec, j); j = k2 + kl
        inner = _enc(0x30, ec[es:j] + _enc(0xa0, oid) + ec[j:es + el])
        return _enc(0x30, der[ps:as_ + al] + _enc(0x04, inner))

    _P256 = bytes.fromhex("06082a8648ce3d030107")
    test(_tls_cfg(_CRT, _wrap_key(_with_params(_kder, _P256),
                                  _os.path.join(_TD, "params.key"))),
         "a valid [0] prime256v1 parameters field is accepted", True)
    test(_tls_cfg(_CRT, _wrap_key(_with_params(_kder, bytes.fromhex("06082a8648ce3d030108")),
                                  _os.path.join(_TD, "wrongcurve.key"))),
         "a [0] naming a different curve is rejected", False)

    # --- audit-report-106: the final Base64 quantum must be whole ------------
    # One stray symbol holds six bits and emits NO byte, so the DER came out
    # identical and every later check passed on text that is not valid Base64.
    # Two or three strays were already refused -- but only because they
    # corrupted the DER, which is luck rather than a check.
    for _n in (1, 2, 3):
        _inc = _os.path.join(_TD, "inc%d.crt" % _n)
        open(_inc, "w").write(_pem.replace("-----END", "A" * _n + "\n-----END"))
        test(_tls_cfg(_inc, _KEY),
             "%d stray base64 symbol(s) before END is rejected" % _n, False)

    # --- audit-report-107: an AlgorithmIdentifier's OID must BE an OID -------
    # Only the tag and a nonzero length were checked, so an OID whose last byte
    # still carried the continuation bit passed: unterminated, naming no
    # algorithm, and identical to its twin so the cross-field comparison agreed
    # as well. Both edits are applied to BOTH copies to keep them equal, which
    # is what makes this a test of the encoding rather than of the comparison.
    _o1, _o2 = 46, 338                 # last byte of each ECDSA-SHA256 OID
    if _der[_o1] == 0x02 and _der[_o2] == 0x02:
        _u = bytearray(_der)
        _u[_o1] = 0x82
        _u[_o2] = 0x82                 # continuation bit set: never terminates
        test(_tls_cfg(_wrap(bytes(_u), _os.path.join(_TD, "badoid.crt")), _KEY),
             "an unterminated OID is rejected", False)
    else:
        bad.append("could not locate the signature OIDs to mutate")
        print("FAIL could not locate the signature OIDs to mutate")
    _m1, _m2 = 44, 336                 # a subidentifier's first byte
    if _der[_m1] == 0x04 and _der[_m2] == 0x04:
        _nm = bytearray(_der)
        _nm[_m1] = 0x80
        _nm[_m2] = 0x80                # leading 0x80: a non-minimal encoding
        test(_tls_cfg(_wrap(bytes(_nm), _os.path.join(_TD, "nonminoid.crt")), _KEY),
             "a non-minimally encoded OID is rejected", False)
    else:
        bad.append("could not locate the OID subidentifiers to mutate")
        print("FAIL could not locate the OID subidentifiers to mutate")

    # --- audit-report-108: issuer and subject are NAMES, not containers ------
    # They reached only der_tiles, which any bounded TLVs satisfy, so an RDN
    # retagged from SET to SEQUENCE tiled just as well and passed. RFC 5280
    # 4.1.2.4: RDNSequence of SETs of AttributeTypeAndValue SEQUENCEs.
    _rdn, _atv, _aoid = 49, 51, 53      # first RDN SET / its ATV SEQ / type OID
    if _der[_rdn] == 0x31 and _der[_atv] == 0x30 and _der[_aoid] == 0x06:
        for _off, _to, _what in ((_rdn, 0x30, "an RDN that is not a SET"),
                                 (_atv, 0x31, "an attribute that is not a SEQUENCE"),
                                 (_aoid, 0x30, "an attribute type that is not an OID")):
            _n = bytearray(_der)
            _n[_off] = _to
            test(_tls_cfg(_wrap(bytes(_n), _os.path.join(_TD, "nm%d.crt" % _off)), _KEY),
                 "%s is rejected" % _what, False)
    else:
        bad.append("could not locate the issuer Name structure to mutate")
        print("FAIL could not locate the issuer Name structure to mutate")

    # --- audit-report-109: the SAME OID rule for Name attributes ------------
    # attr_ok tested only the final byte, a weaker copy of the check alg_id_ok
    # already had -- so "55 80 03" (a non-minimal leading zero) passed there
    # while it was refused in a signature AlgorithmIdentifier. One rule in two
    # places is how they drift; there is one implementation now.
    _cn = 56                            # last byte of the issuer CN OID 55 04 03
    if _der[53] == 0x06 and _der[_cn] == 0x04:
        _a = bytearray(_der)
        _a[_cn] = 0x80
        test(_tls_cfg(_wrap(bytes(_a), _os.path.join(_TD, "attroid.crt")), _KEY),
             "a non-minimal Name attribute OID is rejected", False)
    else:
        bad.append("could not locate the issuer CN attribute OID to mutate")
        print("FAIL could not locate the issuer CN attribute OID to mutate")

    # --- audit-report-111: an attribute VALUE must be a string --------------
    # Report 108 accepted any bounded element here, reasoning that enumerating
    # string types risks refusing a legal certificate. That let a commonName
    # carry an INTEGER, which OpenSSL refuses. The allow-list is the
    # DirectoryString family plus the other string types that appear in DNs.
    _cnv = 58                           # the issuer commonName's value tag
    if _der[_cnv] == 0x0c:
        for _tag, _what in ((0x02, "an INTEGER"), (0x05, "NULL"),
                            (0x30, "a SEQUENCE")):
            _v = bytearray(_der)
            _v[_cnv] = _tag
            test(_tls_cfg(_wrap(bytes(_v), _os.path.join(_TD, "cn%02x.crt" % _tag)),
                          _KEY),
                 "a commonName whose value is %s is rejected" % _what, False)
    else:
        bad.append("could not locate the commonName value tag to mutate")
        print("FAIL could not locate the commonName value tag to mutate")

test('{"log":"/tmp/l","log":"/tmp/m","servers":[]}', "duplicate key rejected",
     False, "duplicate key")
test(json.dumps(base()).replace('"log"', '"logg"', 1), "unknown key rejected",
     False, "unknown key")
test('{"log":"a\\nb","servers":[]}', "escape sequence rejected", False,
     "escape sequences not supported")

# --- scope: a key at the wrong level -------------------------------------
test(srv(max_body=1000), "max_body on a SERVER is unknown", False, "unknown key")
test(base(hsts="max-age=1"), "hsts at TOP level is unknown", False, "unknown key")
test(loc([{"prefix": "/", "root": D, "nosniff": 1}]),
     "nosniff on a LOCATION is unknown", False, "unknown key")

# --- the workers claim ---------------------------------------------------
test(base(workers=0), "workers:0 accepted (= one per CPU)", True)
test(base(workers=257), "workers:257 rejected", False,
     "workers must be between 0 and 256")
c = base(); del c["log"]
test(c, "log is required", False)

# --- hsts is a string, nosniff a flag ------------------------------------
test(srv(hsts=1), "hsts:1 (number) rejected", False)
test(srv(hsts="max-age=31536000"), "hsts as a string accepted", True)
test(srv(nosniff=1), "nosniff:1 accepted", True)
test(srv(nosniff="1"), "nosniff as a string rejected", False)

# --- cert/key pairing and listener homogeneity ---------------------------
test(srv(cert="test/tls/server.crt"), "cert without key rejected", False,
     "both cert and key")
two = base()
two["servers"].append({"host": "127.0.0.1", "port": 61899, "hostname": "y.test",
                       "cert": "test/tls/server.crt", "key": "test/tls/server.key",
                       "locations": [{"prefix": "/", "root": D}]})
test(two, "mixed TLS/plaintext on one listener rejected", False,
     "must all set TLS or none")

# --- location rules ------------------------------------------------------
test(loc([{"prefix": "/", "root": D, "proxy": "127.0.0.1:80"}]),
     "root+proxy rejected", False, "exactly one of")
test(loc([{"prefix": "/", "root": D, "redirect": "https://x/"}]),
     "root+redirect rejected", False, "exactly one of")
test(loc([{"prefix": "/"}]), "location with none of the three rejected", False)
test(loc([{"prefix": "api", "root": D}]), "prefix without a leading / rejected",
     False, "must start with '/'")
test(loc([{"prefix": "/", "redirect": "example.com"}]),
     "redirect without a scheme rejected", False, "http:// or https://")
test(loc([{"prefix": "/", "proxy": "localhost:80"}]),
     "proxy as a DNS name rejected", False, "invalid proxy address")

# --- backend TLS (proxy_tls / proxy_pin / proxy_sni) ---------------------
PIN = "a" * 64
def tlsloc(**extra):
    l = {"prefix": "/api", "proxy": "127.0.0.1:8080"}
    l.update(extra)
    return loc([{"prefix": "/", "root": D}, l])
test(tlsloc(proxy_tls=1, proxy_pin=PIN, proxy_sni="b.internal"),
     "backend TLS: proxy_tls + pin + sni accepted", True)
test(tlsloc(proxy_tls=1, proxy_pin=PIN),
     "backend TLS: proxy_tls + pin (no sni) accepted", True)
test(tlsloc(proxy_tls=1),
     "backend TLS: proxy_tls without a pin rejected", False, "requires proxy_pin")
test(tlsloc(proxy_tls=1, proxy_pin="abcd"),
     "backend TLS: short pin rejected", False, "64 hex")
test(tlsloc(proxy_tls=1, proxy_pin="z" * 64),
     "backend TLS: non-hex pin rejected", False, "64 hex")
test(tlsloc(proxy_tls=2, proxy_pin=PIN),
     "backend TLS: proxy_tls out of range rejected", False, "0 or 1")
test(loc([{"prefix": "/", "root": D, "proxy_tls": 1, "proxy_pin": PIN}]),
     "backend TLS: proxy_tls on a non-proxy location rejected", False,
     "need a proxy location")
test(srv(host="localhost"), "host as a name rejected", False,
     "must be an IPv4 or IPv6 literal")
test(srv(host="::"), 'host "::" accepted (dual-stack wildcard)', True)
test(srv(host="0.0.0.0"), 'host "0.0.0.0" accepted', True)
test(srv(host="::1"), "host ::1 (specific IPv6 literal) accepted", True)
test(srv(host="2001:db8::1"), "host 2001:db8::1 accepted", True)
test(srv(host="::ffff:1.2.3.4"), "host ::ffff:1.2.3.4 (mapped) accepted", True)
test(srv(host="gg::"), "host gg:: (bad IPv6) rejected", False,
     "must be an IPv4 or IPv6 literal")
test(srv(host="fe80::1%eth0"), "host with a zone id rejected", False,
     "must be an IPv4 or IPv6 literal")
test(srv(host="::", v6only=1), 'host "::" v6only accepted', True)
test(srv(host="::", v6only=2), "v6only out of range rejected", False,
     "v6only must be 0 or 1")
test(loc([{"prefix": "/", "root": "/nonexistent-dir"}]),
     "root that does not exist rejected by --test", False,
     "not an existing directory")
test(base(log="/nonexistent-dir/x.log"),
     "log directory that does not exist rejected by --test", False,
     "log's directory does not exist")
test(srv(hsts=1), "hsts:1 names the shape to use", False,
     "takes the header VALUE as a string")

# --- limits --------------------------------------------------------------
# max_body's range, which was the one range claim never asserted here — and
# the one that was false. The doc and this file are two hand-written
# transcriptions of the same table, so a row nobody asserts drifts silently:
# the doc and the key's own error message both promised 68719476736 while the
# parser refused anything past 4294967296, a generic 2^32 guard overriding the
# specific range above it.
test(base(max_body=0), "max_body 0 rejected", False, "max_body must be at least 1")
test(base(max_body=1), "max_body 1 accepted", True)
test(base(max_body=4294967297), "max_body past the old 2**32 guard accepted", True)
test(base(max_body=18446744073709551615), "max_body at 2**64-1 accepted", True)
test(base(max_body=18446744073709551616), "max_body past 64 bits rejected", False,
     "number too large")

test(base(timeout=3601), "timeout above 3600 rejected", False)
test(base(timeout=3600), "timeout at 3600 accepted", True)
# rate_limit: the request-rate control. 0 is legal and means off, which is the
# claim that keeps every config written before the key behaving as it did.
test(base(rate_limit=0), "rate_limit:0 accepted (means off)", True)
test(base(rate_limit=1), "rate_limit at 1 accepted", True)
test(base(rate_limit=1000000), "rate_limit at 1000000 accepted", True)
test(base(rate_limit=1000001), "rate_limit above 1000000 rejected", False,
     "rate_limit must be between 0 and 1000000")
test(srv(rate_limit=10), "rate_limit on a SERVER is unknown", False, "unknown key")

# error_log: the diagnostics stream. Unset is the interesting claim -- one file
# for both, which is what every config written before the key relies on.
test(base(error_log=os.path.join(D, "e.log")), "error_log accepted", True)
test(base(error_log=""), "empty error_log rejected", False,
     "error_log must not be empty")
test(srv(error_log=os.path.join(D, "e.log")), "error_log on a SERVER is unknown",
     False, "unknown key")

# tunnel_timeout: the upgraded-connection deadline, separate again.
test(base(tunnel_timeout=86401), "tunnel_timeout above 86400 rejected", False,
     "tunnel_timeout must be between 1 and 86400")
test(base(tunnel_timeout=0), "tunnel_timeout:0 rejected (unset follows timeout)",
     False, "tunnel_timeout must be between 1 and 86400")
test(base(tunnel_timeout=86400), "tunnel_timeout at 86400 accepted", True)
test(srv(tunnel_timeout=60), "tunnel_timeout on a SERVER is unknown", False, "unknown key")

# proxy_timeout: the upstream deadline, separate from the client idle timeout.
# The default claim is the interesting one -- "whatever timeout is" -- because
# it is what keeps every config written before the key behaving identically.
test(base(proxy_timeout=3601), "proxy_timeout above 3600 rejected", False,
     "proxy_timeout must be between 1 and 3600")
test(base(proxy_timeout=0), "proxy_timeout:0 rejected (unset is how you follow timeout)",
     False, "proxy_timeout must be between 1 and 3600")
test(base(proxy_timeout=1), "proxy_timeout at 1 accepted", True)
test(base(proxy_timeout=3600), "proxy_timeout at 3600 accepted", True)
test(srv(proxy_timeout=5), "proxy_timeout on a SERVER is unknown", False,
     "unknown key")

test(base(drain_timeout=3601), "drain_timeout above 3600 rejected", False,
     "drain_timeout must be between 1 and 3600")
test(base(drain_timeout=0), "drain_timeout:0 rejected (no way to disable it)",
     False, "drain_timeout must be between 1 and 3600")
test(base(drain_timeout=1), "drain_timeout at 1 accepted", True)

# spill_dir: the doc says it must exist, must support O_TMPFILE, is a global,
# and is <= 255 bytes. It also says the default is /tmp -- which the doc warns
# about rather than recommends, so what is asserted is that omitting the key is
# ACCEPTED, not that /tmp is a good idea.
test(base(spill_dir="/no/such/directory"), "spill_dir must exist", False,
     "spill_dir is not an existing directory")
test(base(spill_dir="/proc"), "spill_dir must support O_TMPFILE", False,
     "does not support O_TMPFILE")
test(base(spill_dir=""), "spill_dir may not be empty", False,
     "spill_dir must be a non-empty path")
test(base(spill_dir="x" * 256), "spill_dir over 255 bytes rejected", False,
     "spill_dir must be a non-empty path")
test(base(spill_dir=D), "spill_dir on a real directory accepted", True)
test(base(), "spill_dir is optional (defaults to /tmp)", True)
test(srv(drain_timeout=30), "drain_timeout on a SERVER is unknown", False,
     "unknown key")
test(srv(port=65536), "port above 65535 rejected", False)

# port: 0 means "let the kernel choose" (doc: the port row and the note under
# it). The key stays REQUIRED, which is what keeps a random port something the
# config asked for rather than something it forgot -- so both halves are
# asserted, not just the permissive one.
test(srv(port=0), "port 0 accepted (kernel-chosen)", True)
nokey = base()
del nokey["servers"][0]["port"]
test(nokey, "port key still required (0 is deliberate, not missing)", False,
     "server requires host, port, hostname and locations")

# port_file: a global, <= 255 bytes, optional, and not a server key.
test(base(port_file=""), "port_file may not be empty", False,
     "port_file must be a non-empty path")
test(base(port_file="x" * 256), "port_file over 255 bytes rejected", False,
     "port_file must be a non-empty path")
test(base(port_file=os.path.join(D, "ports")), "port_file path accepted", True)
test(base(), "port_file is optional", True)
test(srv(port_file="/tmp/x"), "port_file on a SERVER is unknown", False,
     "unknown key")
big = base()
big["servers"][0]["locations"] = [{"prefix": "/p%d" % i, "root": D}
                                  for i in range(9)]
test(big, "9 locations rejected (max 8)", False, "too many locations")

print()
print("all claims hold" if not bad
      else "%d FAILED: %s" % (len(bad), ", ".join(bad)))
sys.exit(1 if bad else 0)
