# Audit Report 118

Audited commit `40a790c` (`tls: the leaf must permit server authentication (report 117)`), 2026-08-28.

This full-sweep pass rechecked the new leaf Key Usage/EKU validation, DER and extension framing, key pairing, and validity handling. The parser confirms that Validity contains two time-typed values, but neither preflight nor startup compares them with the current time. As a result, a cryptographically matching leaf that cannot be used now is approved.

No production code or test was changed in this audit. Only this report was added.

## Finding 1 — Preflight accepts expired and not-yet-valid TLS certificates

**Severity:** Medium  
**Confidence:** High  
**Status:** Open

[`tbs_walk`](/home/linnea/linnea/src/server/linnea_pem.asm:1674) checks only that Validity has two UTCTime or GeneralizedTime elements. The credential loader then performs leaf-purpose and key-pair checks, but no path compares `notBefore` or `notAfter` with wall-clock time. Thus `--test` reports success for a certificate that clients must reject at the present time.

RFC 5280 defines Validity as the interval in which the CA warrants that the public key may be used, and path validation requires the current time to fall within it ([RFC 5280 §§4.1.2.5 and 6.1.3](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.5)).

### Reproduction

Generate a self-signed leaf with the repository's matching P-256 key and an already elapsed interval:

```sh
openssl x509 -new -key test/tls/server.key -subj /CN=localhost -set_serial 1 \
  -not_before 20200101000000Z -not_after 20200102000000Z -out expired.crt

# Configure expired.crt with test/tls/server.key.
./bin/linnea --config config.json --test  # exits 0 (incorrect)
openssl verify -purpose sslserver -CAfile expired.crt expired.crt
# error 10: certificate has expired
```

The same result occurs with a future `notBefore` time; OpenSSL reports the certificate is not yet valid. These fixtures retain a valid certificate signature and a matching public/private key, isolating the missing validity-window check.

### Impact

An operator can deploy or hot-upgrade to expired or prematurely issued credentials after a successful local preflight. Linnea sends them, while standards-compliant clients abort certificate validation, producing a preventable TLS outage.

### Recommended fix

For the configured leaf, parse the two Validity values according to RFC 5280's UTCTime/GeneralizedTime forms and compare them with the current UTC time during `--test` and normal startup. Reject `notBefore` in the future or `notAfter` in the past. Keep intermediate time handling separate from this leaf-usability gate unless full chain validation is added. Add fixed expired and future-validity matching-leaf fixtures.

---

## Resolution (2026-08-28)

**CONFIRMED. Detected and reported — deliberately NOT enforced.** I am
declining the recommendation to reject, and the reasoning matters more than the
code.

`--test` and startup now parse both Validity times (UTCTime and
GeneralizedTime, via the existing `linnea_time_days_from_civil`), compare them
with CLOCK_REALTIME, and print a prominent warning to **stderr** — which is
where the operator sees it, since `--test` never opens the log file.

### Why rejecting would be the wrong fix here

**nginx and Apache both start on an expired certificate.** Refusing would turn
a silently-failed renewal — a degraded state clients merely complain about —
into a total outage the operator cannot restart out of. On this host certbot
renews unattended, so that scenario is not hypothetical.

It would also **block the hot upgrade**: the upgrade runs `--test` on the new
binary, so an expired certificate would refuse the very deploy that might carry
the fix. The certificate's expiry is orthogonal to whether the new binary is
good.

And a **config check whose verdict changes with the clock is not a config
check**: the same files would pass today and fail tomorrow with nothing edited.

Making it fatal is a one-line change if that trade is ever wanted. It is the
operator's call, not mine, and it is stated in the code so it can be found.

### A link dependency caught before it broke five products

The first implementation put the epoch arithmetic in `linnea_pem.asm`, which
needs `linnea_time_days_from_civil`. **Five harnesses link `linnea_pem.o`
without `linnea_time.o`** — SELFTEST, TLSTEST, TLSCLIENT, QUICCERT and QUICMSG
— so that would have broken all five, exactly as report 96's lib-calling-a-
server-symbol broke `linnea-probe`. Checked the Makefile object lists BEFORE
adding the dependency this time. `pem` now only extracts the two time strings;
`ktls`, which already links time, owns the clock and the policy.

**The suite was not run: the operator asked for the fix only.** The last full
suite remains 1193/0 at `0e3fe0e`, which is what prod runs; reports 107-118 are
not covered by it.
