# Audit Report 117

Audited commit `990aa8d` (`pkcs8: walk the attributes content, not just its wrapper (report 116)`), 2026-08-28.

This full-sweep pass rechecked the repaired PKCS#8 attributes path, PEM framing, DER structure, and the transition from certificate parsing to TLS credential use. The parser intentionally leaves extension values opaque, but the loader then uses the leaf to produce TLS CertificateVerify signatures. It does not enforce the extension restrictions that make that signature use legal, so `--test` can approve a syntactically valid, matching certificate that is unsuitable for a TLS server.

No production code or test was changed in this audit. Only this report was added.

## Finding 1 — Preflight ignores TLS server key-usage and purpose restrictions

**Severity:** Medium  
**Confidence:** High  
**Status:** Open

The certificate walk validates only the outer `Extension` framing and deliberately leaves `extnValue` opaque in [`exts_ok`](/home/linnea/linnea/src/server/linnea_pem.asm:1343). The subsequent pairing code proves that the private scalar matches the leaf public key, but it never checks whether the leaf is permitted to use that key for a server CertificateVerify signature.

TLS 1.3 requires that a server certificate allow signing: if Key Usage is present, `digitalSignature` MUST be set ([RFC 8446 §4.4.2.2](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.2.2)). A server-authentication purpose check also rejects a leaf whose Extended Key Usage is limited to `clientAuth`.

### Reproduction

Create either self-signed P-256 certificate below using the repository's matching `test/tls/server.key`, then configure it as the TLS certificate and run the normal preflight.

```sh
# The key is cryptographically matching, but cannot sign TLS server authentication.
openssl req -new -x509 -key test/tls/server.key -subj /CN=localhost -days 1 \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,keyCertSign' \
  -addext 'extendedKeyUsage=serverAuth' -out bad-key-usage.crt

# The key can sign, but the certificate is limited to client authentication.
openssl req -new -x509 -key test/tls/server.key -subj /CN=localhost -days 1 \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature' \
  -addext 'extendedKeyUsage=clientAuth' -out bad-eku.crt

./bin/linnea --config config.json --test       # exits 0 for either certificate
openssl verify -purpose sslserver -CAfile bad-key-usage.crt bad-key-usage.crt
openssl verify -purpose sslserver -CAfile bad-eku.crt bad-eku.crt
# both verification commands fail: unsuitable certificate purpose
```

### Impact

An operator can deploy or hot-upgrade to a certificate/key pair that Linnea can sign with but standards-aware clients reject for server authentication. The service then presents a locally preflighted credential yet fails TLS handshakes, creating an avoidable availability outage.

### Recommended fix

During leaf-only credential preflight, decode recognized Key Usage and Extended Key Usage extension values. If Key Usage is present, require `digitalSignature`; if Extended Key Usage is present, require `id-kp-serverAuth`. Keep extension parsing for intermediates structural and algorithm-agnostic. Add matching-key regressions for both generated certificates above.

---

## Resolution (2026-08-28)

**CONFIRMED and FIXED.** 186 claims (was 182).

This is the first finding in this arc that is **semantic rather than syntactic**
— every earlier one was "is this well-formed DER". Worth noting because it
changes which reference command answers the question: `openssl x509 -noout`
*parses* both bad certificates happily; it is `openssl verify -purpose
sslserver` that refuses them. The comparison table for this report uses the
purpose check accordingly.

`linnea_x509_leaf_usage_ok` now decodes Key Usage and Extended Key Usage on the
leaf: if Key Usage is present, `digitalSignature` must be set; if Extended Key
Usage is present, it must contain `id-kp-serverAuth` or
`anyExtendedKeyUsage`. Its own diagnostic names which rule failed.

### Two scope decisions, both measured

**ABSENT stays legal.** Every certificate in this tree — `server.crt`,
`sni.crt`, the multi-RDN and UTF-8 fixtures, all three generated pairs — has
NEITHER extension, and OpenSSL's sslserver purpose check passes them all.
Requiring either extension to be present would have refused every credential in
the repository, and prod's certbot leaf besides.

**LEAF ONLY.** An issuer legitimately carries `keyCertSign` and no
`serverAuth`, so applying this to chain entries would break any real chain.
`bigchain.crt` (7 certificates) is the control and still loads.

Both branches needed built fixtures — the existing certificates carry no
extensions at all, so nothing in the tree could reach the present-but-wrong
paths. `anyExtendedKeyUsage` needed a third.

**The suite was not run: the operator asked for the fix only.** The last full
suite remains 1193/0 at `0e3fe0e`, which is what prod runs; reports 107-117 are
not covered by it.
