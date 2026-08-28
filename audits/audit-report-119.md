# Audit Report 119

Audited commit `5189818` (`tls: report an out-of-window certificate, do not refuse it (report 118)`), 2026-08-28.

This full-sweep pass rechecked the deliberate validity-warning policy, leaf usage checks, PEM/DER framing, and the remaining client-visible certificate properties. It confirms two independent preflight gaps: the configured virtual-host name is not bound to the leaf certificate, and certificate signatures are never cryptographically verified.

No production code or test was changed in this audit. Only this report was added.

## Finding 1 — The configured hostname is not checked against the leaf certificate

**Severity:** Medium  
**Confidence:** High  
**Status:** Open

The loader proves that the configured private key matches the leaf SPKI and checks a small set of TLS-use extensions, but it does not inspect Subject Alternative Name or Common Name against the server configuration's `hostname`. A credential for another DNS name therefore passes `--test` and is selected for this virtual host.

### Reproduction

Create a matching certificate that only identifies a different host, configure it on a `hostname: "localhost"` server, and verify it for localhost:

```sh
openssl req -new -x509 -key test/tls/server.key -subj /CN=wrong.example -days 1 \
  -addext 'subjectAltName=DNS:wrong.example' -out wrong-name.crt

./bin/linnea --config config.json --test  # exits 0 (incorrect)
openssl verify -purpose sslserver -verify_hostname localhost \
  -CAfile wrong-name.crt wrong-name.crt
# error 62: hostname mismatch
```

### Impact

An operator can deploy or hot-upgrade a certificate/key pair that is internally consistent but cannot authenticate the configured site. Clients validating the requested DNS name abort the TLS handshake, despite a successful local preflight.

### Recommended fix

For each TLS server, validate its configured hostname against the leaf Subject Alternative Name DNS entries (and Common Name only under the applicable fallback rules). Support normal exact names and constrained wildcard matching; reject an unmatched certificate before it is installed.

## Finding 2 — Certificate signature integrity is not checked

**Severity:** Medium  
**Confidence:** High  
**Status:** Open

[`tbs_walk`](/home/linnea/linnea/src/server/linnea_pem.asm:1531) validates Certificate structure and requires the inner and outer AlgorithmIdentifier encodings to agree, but no loader path verifies `signatureValue` over `tbsCertificate`. The source describes this path as syntax-only at [line 1801](/home/linnea/linnea/src/server/linnea_pem.asm:1801), so a corrupted signed certificate is framed and served.

RFC 5280 path validation includes signature verification for each certificate ([RFC 5280 §6.1.3](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.3)).

### Reproduction

Corrupt only the repository certificate's signature and retain the matching private key:

```sh
openssl x509 -in test/tls/server.crt -badsig -out badsig.crt

./bin/linnea --config config.json --test  # exits 0 (incorrect)
openssl verify -check_ss_sig -purpose sslserver -CAfile badsig.crt badsig.crt
# error 7: certificate signature failure
```

`-check_ss_sig` is necessary because OpenSSL otherwise treats the self-signed certificate supplied as a trust anchor without verifying its self-signature.

### Impact

Corruption or a partially written renewal can pass preflight and be transmitted to every client. Clients that validate the certificate chain reject it, causing a TLS availability failure. This is distinct from leaf/key matching: CertificateVerify proves possession of the leaf key, not that an issuer authorized the certificate bytes.

### Recommended fix

Validate the configured chain from leaf through its supplied issuer certificates: require issuer/subject linkage and verify each certificate signature using the issuer SPKI, while leaving trust-anchor selection to the operator or platform trust store. If full multi-algorithm path validation is intentionally outside scope, at least verify the self-signed case and clearly make unverified issuer signatures a startup warning or explicit opt-in rather than reporting the certificate as checked.

## Resolution

Both findings reproduced exactly as written and both are fixed. Each fix departs
from the letter of its recommendation, in one case deliberately; the measurements
behind that are below.

### Finding 1 — fixed as a WARNING, not a refusal

`linnea_x509_leaf_host_ok` (in `linnea_pem.asm`) matches the configured hostname
against the leaf, and `linnea_ktls.asm` warns on stderr when it does not match.
RFC 6125 semantics: when the certificate carries at least one SAN dNSName the CN
is ignored entirely, and only a certificate with no dNSName falls back to the CN.
Wildcards match exactly one leftmost label, and only when what follows still
contains a dot -- so `*.com` cannot cover `example.com`.

**The report recommends "reject an unmatched certificate before it is installed".
That part is declined, on evidence.** Two configurations in this repository
deliberately serve a hostname the certificate does not cover:

| config | hostname | certificate names |
|---|---|---|
| `test/configs/tls-coalesce.json` | `alias.test` | `DNS:localhost` |
| `test/configs/tls-h3-mixed.json` | `other.localhost` | `DNS:localhost` |

Both are live, passing fixtures, and both are legitimate: HTTP/2 connection
coalescing serves a vhost over a connection authenticated for *another* of its
names, so the client -- not the server -- decides the name is acceptable.
Refusing would break connection coalescing and turn a working deployment into a
startup failure. This is the same trade report 118 made for expiry, and the
warning sits beside that one.

A hostname that is an IP literal is skipped rather than warned about: it can
never appear as a dNSName, and this build does not read iPAddress SAN entries,
so it has nothing to say about one.

### Finding 2 — fixed for the self-signed case, which is the report's own fallback

`linnea_x509_leaf_selfsig` returns the tbsCertificate element, the signature, and
whether issuer and subject are byte-identical; `linnea_ktls.asm` hashes the TBS
and verifies with `linnea_p256_ecdsa_verify_der` against the leaf's own point.
**A verification that runs and fails is fatal.**

Full chain verification was measured and rejected as unsafe here:

- `test/tls/bigchain.crt` holds 7 certificates, but its leaf is **self-signed** --
  the other six are padding for QUIC amplification testing, not a chain.
  Link-by-link verification would refuse `tls-h3-bigcert.json`.
- This build has P-256/SHA-256 only. Real issuers are commonly RSA or P-384
  (Let's Encrypt's R10/R11 and E5/E6), so their signatures cannot be checked at
  all.

An issued certificate is therefore left **unverified and silent** rather than
warned about: a warning would fire on every boot of a perfectly good production
certificate, and the loader never claimed in text to have checked it. A leaf
signed by an EC CA and one signed by an RSA CA were both confirmed to load
silently, so production is unaffected.

### Verified against OpenSSL

Every case below was run against the built binary with `openssl`'s independent
verdict printed beside it. All nine agree.

| case | linnea | openssl |
|---|---|---|
| `openssl x509 -badsig` self-signed leaf | refused | signature failure |
| valid certificate for `wrong.example` | warns, loads | hostname mismatch |
| `*.example.test` vs `a.example.test` | match | OK |
| `*.example.test` vs `x.y.example.test` | warns | fails |
| `*.example.test` vs `example.test` | warns | fails |
| `*.test` vs `a.test` (too broad) | warns | fails |
| SAN present, only CN matches | warns | fails |
| no SAN at all, CN matches | match | OK |
| SAN `LoCalHost` vs host `localhost` | match | OK |
| leaf issued by an EC CA | loads silently | (not applicable) |
| leaf issued by an RSA CA | loads silently | (not applicable) |

**Acceptance control first:** every TLS configuration in `test/configs/` was
loaded before any rejection test was written. All still load, with exactly the
two expected name warnings and no other change. `bad-cert-only.json` and
`bad-tls-mismatch.json` fail identically to before (both are deliberate-failure
fixtures, confirmed against a stashed tree).

### Coverage

- `test/shards/base/10-config.sh`: the forged signature is refused, the name
  mismatch warns, and -- the control that matters -- a *matching* certificate
  warns about nothing. Without that last check a build that warned about every
  certificate would pass the other two.
- `test/configs/doc_claims_test.py`: 187 -> 190 claims. The new ones include the
  **scope control** -- the same broken signature on an *issued* certificate is
  left unverified rather than refused, so a build that rejected everything
  outright could not pass.

### Two incidental defects found while verifying this

1. **A pre-existing link breakage, confirmed against a stashed tree.**
   `bin/linnea-tlstest`, `bin/linnea-tlsclient`, `bin/linnea-quiccert`,
   `bin/linnea-quiccv`, `bin/linnea-quicfin` and `bin/linnea-quichs` had not
   linked since `linnea_random.o` was introduced -- four object lists never
   gained it, and `make all` does not cover these targets. Fixed in the Makefile;
   all nine products now build.

2. **A skipped-claim bug I introduced and caught by counting.** The first version
   of the `_unself` helper was written at column 0 inside an indented block,
   which silently absorbed the following 40 claims into its body as dead code
   after its `return`. The file still printed "all claims hold" -- 147 claims
   ran instead of 187. This is the exact failure the file's own comment warns
   about ("a skipped check reads as a pass"), and only comparing claim *counts*
   before and after exposed it.
