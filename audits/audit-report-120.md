# Audit Report 120

Audited commit `13584fd` (`test: keep nginx's workers privileged so the interop fixture can read its own files`), 2026-08-28.

This pass examined the local TLS credential preflight, concentrating on the X.509
extensions that determine whether clients can use a configured leaf. It found
that an otherwise valid certificate carrying an unrecognised **critical**
extension is accepted and served. No production code or test was changed in
this audit; only this report was added.

## Finding 1 — Unknown critical certificate extensions are accepted

**Severity:** Medium  
**Confidence:** High  
**Status:** Open

RFC 5280 requires an implementation to reject a certificate when it encounters
a critical extension that it does not recognise or cannot process ([RFC 5280
§4.2](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2)). The loader
walks extensions solely to evaluate `keyUsage` and `extendedKeyUsage`:
[`linnea_x509_leaf_usage_ok`](../src/server/linnea_pem.asm#L1920) advances past
every other Extension without inspecting its `critical` flag or OID. The
structural walk used for every chain entry similarly performs syntax validation
only ([`linnea_x509_cert_wellformed`](../src/server/linnea_pem.asm#L1805)).
Consequently, an unknown critical extension passes `--test` and is sent to
clients even though conforming validators refuse it.

### Reproduction

Starting from the repository root, create a matching self-signed certificate
with a private critical extension, substitute it into the ordinary TLS fixture,
and compare the two validators:

```sh
d=$(mktemp -d /tmp/linnea-audit-XXXXXX)
openssl req -new -x509 -key test/tls/server.key -subj /CN=localhost -days 1 \
  -addext '1.2.3.4=critical,DER:05:00' -out "$d/unknown-critical.crt"
sed "s#test/tls/server.crt#$d/unknown-critical.crt#" test/configs/tls.json > "$d/config.json"

./bin/linnea --config "$d/config.json" --test
# exits 0 (incorrect)

openssl verify -purpose sslserver -CAfile "$d/unknown-critical.crt" \
  "$d/unknown-critical.crt"
# error 34 at 0 depth lookup: unhandled critical extension
```

The acceptance control also passed: the unmodified
`./bin/linnea --config test/configs/tls.json --test` exits zero with no stderr.

### Impact

An operator can preflight and deploy a certificate that normal TLS clients will
reject. This is especially plausible when a CA introduces a critical extension
that Linnea does not yet understand, or when a certificate is corrupted into a
different but structurally valid extension. The immediate effect is a TLS
availability outage after reload despite a successful local config check.

### Recommended fix

While walking each leaf extension, parse the optional `critical` BOOLEAN. Keep
the currently implemented OIDs in an explicit recognised set, and reject a
critical extension outside that set (or fully validate any additional critical
extension before adding it to the set). Apply the same policy to every supplied
chain entry if the preflight continues to describe the whole chain as checked.

Add a rejection fixture for the private critical OID above and a matching
control with the same unknown OID marked non-critical; the latter must load, so
a blanket refusal of unknown extensions cannot pass the test.

## Resolution (2026-08-28)

**CONFIRMED and FIXED.** Reproduced before believing: the report's own
reproduction was run verbatim against `13584fd` and `--test` exited 0 while
`openssl verify -purpose sslserver` gave `error 34 ... unhandled critical
extension`. The acceptance control ran first and passed — the unmodified
`test/configs/tls.json` exits 0 with no stderr.

`ext_critical_ok` now walks every extension and, for each one marked critical,
requires its OID to be one this build acts on: `keyUsage` and `extKeyUsage`
(read by `linnea_x509_leaf_usage_ok`), `subjectAltName` (`linnea_x509_leaf_host_ok`)
and `basicConstraints` (`bc_value_ok`). Anything else refuses the certificate.
It runs on EVERY chain entry, not just the leaf, because a client refuses either.

### basicConstraints had to join the recognised set in the same change

The recommendation as written — "keep the currently implemented OIDs in an
explicit recognised set" — would have **refused the entire corpus and
production with it.** The implemented set was `keyUsage`, `extKeyUsage`,
`subjectAltName`. `basicConstraints` (2.5.29.19) appears nowhere in this build,
and it is marked critical on all six certificate fixtures in this tree and on
all three certificates of the live chain:

```
CN=linnea.amberbio.com          Key Usage: critical   Basic Constraints: critical
C=US, O=Let's Encrypt, CN=YE2   Key Usage: critical   Basic Constraints: critical
C=US, O=ISRG, CN=Root YE        Key Usage: critical   Basic Constraints: critical
```

That is the report-114 shape exactly: a preflight turning a legal file into an
outage. Measured, not assumed, before a line was written.

Its parse is deliberately **syntax only**. `cA:TRUE` on a leaf is not an error
— every self-signed fixture here is its own CA and OpenSSL's `sslserver`
purpose accepts them — and `pathLenConstraint` constrains a chain this build
never assembles, so there is nothing it could honestly enforce. Recognising the
extension is what RFC 5280 4.2 asks for; the parse is what makes "recognised"
mean we looked.

### The refusal is reported as itself

The check was first folded into `linnea_x509_cert_wellformed` and that was
backed out. Its contract is syntax only, and sharing its failure path made a
perfectly well-formed certificate report `cannot load TLS certificate chain
(not PEM CERTIFICATEs?)` — which sends the operator to look for a corrupt file.
It is now its own step in the chain walk returning `-3`, with its own message:

```
linnea: the certificate chain carries a CRITICAL X.509 extension this build does
not implement: RFC 5280 4.2 requires clients to reject it, so serving it would
fail every handshake
```

### The critical BOOLEAN is tested by value, not by presence

DER says FALSE is the default and MUST then be omitted, but a non-conforming
encoder can still write an explicit `00`. `ext_is_critical` tests the value, so
such an extension reads as non-critical rather than becoming a refusal of a
certificate every client accepts.

### Coverage

`test/tls/unknown-critical.crt` and `test/tls/unknown-noncritical.crt` carry the
private arc `1.2.3.4`, which can never become something this build implements.
Both are signed by `server.key`, so a refusal cannot be the key-pairing check
firing instead, and both expire in 2036 like `server.crt`.

The non-critical control is the one that matters: an unrecognised extension is
only fatal when it is critical, so a build that refused unknown extensions
outright would pass the rejection test while rejecting certificates the whole
world ships. A/B confirms both directions — the pre-change binary accepts the
critical fixture, this one refuses it, and both accept the non-critical one.

### Measurements

- **Acceptance controls FIRST**: all 61 configs in `test/configs/` were run
  against the pre-change and post-change binaries and every verdict is
  identical. Not a sample — the whole directory, diffed.
- **A real certificate**: `test/tls/prod_cert_check.sh` passes, whole chain
  parsed, 3 certs.
- **Independent oracle**: OpenSSL agrees on both fixtures — `verification
  failed` for the critical one, `OK` for the non-critical one.
- **Fast suite 1186 passed, 0 failed** across three jobs in 488s; the base
  shard went 162 to 164 on the two new checks. The full suite has NOT been run
  and must be before deploying.
