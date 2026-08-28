# Working an audit report

Reports arrive as `audits/audit-report-NN.md`, written by a different agent than
the one that fixes them. This is the loop, and the reasons behind the steps that
look like overhead. Every one of them is here because skipping it cost something.

## 1. Reproduce before believing

A report is a claim, not a finding. Build the fixture it describes and run it.
Reports in this series have been right that something was wrong and wrong about
what — and a fix aimed at the wrong cause passes its own test.

If a recommendation should be declined, decline it **with a measurement**, in the
Resolution. Two reversals in this arc came from asserting what OpenSSL would do
rather than asking it.

## 2. Acceptance controls FIRST

Before writing a single rejection test, confirm that everything which loaded
before still loads. Tightening a parser is how you refuse something legitimate,
and that failure is invisible if you only test the thing you meant to reject.

For the TLS loader that means every config in `test/configs/`, not a sample.

## 3. Ask an independent oracle

When the change is about a format someone else also parses, print their verdict
beside ours and flag disagreements:

```sh
openssl verify -purpose sslserver -CAfile c.pem c.pem          # chain/signature
openssl verify -verify_hostname H -CAfile c.pem c.pem          # names
openssl x509 -in c.pem -badsig -out badsig.pem                 # a broken signature
```

Report 114 rejected a certificate OpenSSL accepts. That is the worst outcome
available — a preflight turning a legal file into an outage.

## 4. Load a REAL certificate

**Run this whenever a change touches certificate, PEM, or DER code:**

```sh
test/tls/prod_cert_check.sh            # or: prod_cert_check.sh chain.pem ...
```

It loads a genuinely issued chain against a key that deliberately does not
match, so no private key is ever needed: reaching `different identities` proves
every certificate parsed. It exits `0` pass, `1` fail, `3` skip, and runs inside
the suite's base shard.

This exists because report 114 shipped a defect that refused **every real
certificate**: an extensions wrapper end kept in `r8` across a `der_any` call,
which clobbers `r8` only in its `0x82` two-byte length path. Extensions under
256 bytes survived; 256 or more did not. Every fixture in this tree sits under
that line and every real certificate sits over it, so a **1209-check full suite
passed and the production reload was rejected**. See `2764ba8`.

The general rule it stands for: **when a path branches on a size or an encoding
form, a fixture must cross the boundary.** "It has extensions" is not coverage.
`test/tls/bigext.crt` (497 bytes, `0x82`) holds that line synthetically; only a
real chain carries SCT lists, policies, AIA, a foreign issuer DN, and a
signature algorithm this build cannot verify.

## 5. Add coverage that fails on a blanket build

Every new check needs a control that a *broken* implementation cannot pass. A
test asserting "the bad thing is rejected" is satisfied by an implementation
that rejects everything. So pair it:

- the malformed input is refused, **and** the well-formed one is accepted;
- the warning fires, **and** a matching certificate stays silent.

Prove the pairing by A/B — run the new test against the pre-fix binary and watch
it fail. A test never seen failing is not known to test anything.

Count claims before and after (`test/configs/doc_claims_test.py`). It prints
"all claims hold" whether it ran 187 claims or 147; only the count exposes a
block that stopped executing.

## 6. Write the Resolution

Append `## Resolution` to the report: what was reproduced, what was fixed, what
was declined and on what evidence, the oracle comparison, and anything found
along the way. Say plainly when the report was wrong.

## 7. The suite, and the deploy

`./test/run_shards.sh` is the fast run and does **not** gate a deploy;
`LINNEA_SUITE=full` does. A green suite is not permission to deploy — the
operator decides when a series is done.

Deploy is `sudo make install && sudo systemctl reload linnea` — **reload, never
restart**. The reload re-execs and runs a config check first, so a bad binary is
refused and the old workers keep serving. Confirm it actually took:

```
binary upgrade complete: new workers up, draining old   # in linnea-error.log
```

`upgrade rejected: new binary failed the config check` means production is still
on the old binary and something is refused. Reproduce it locally — production
certificates are world-readable at `/etc/linnea/certs/*/fullchain.pem`, which is
what step 4 automates.
