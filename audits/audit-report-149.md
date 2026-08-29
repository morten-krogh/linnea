# Audit Report 149

Audited commit `1e28409` (`audit 147: no issues found`), 2026-08-29.

This pass examined HTTP-date parsing and its use by static conditional requests
and range gating across HTTP/1, HTTP/2, and HTTP/3. It found one shared parser
defect: dates whose day does not exist in their named month are converted into a
different, real date and allowed to control the response. No source, test, or
configuration file was changed in this audit; only this report was added.

## Finding 1 — Nonexistent HTTP dates satisfy conditional requests

**Severity:** Low  
**Confidence:** High  
**Status:** Open

`linnea_time_parse_http_date` validates a numeric day only as 1 through 31
([`linnea_time.asm`](../src/server/linnea_time.asm#L324)), without checking the
day against its month or applying the Gregorian leap-year rules. It then passes
that unchecked triple directly to `linnea_time_days_from_civil`
([`linnea_time.asm`](../src/server/linnea_time.asm#L382)). That conversion
formula assumes a valid civil date; given an impossible one, it normalizes the
overflow into the following month. For example, 29 February 2099 becomes a
March timestamp instead of failing to parse.

The HTTP/1 `If-Modified-Since` path explicitly treats `-1` as an unparseable
date to ignore, but compares every other result with the file mtime and can send
304 ([`linnea_http.asm`](../src/server/linnea_http.asm#L2396)). HTTP/2 and
HTTP/3 call the same parser for `If-Modified-Since` and
`If-Unmodified-Since`; the shared `If-Range` helper calls it as well
([`linnea_static.asm`](../src/server/linnea_static.asm#L969)). The defect is
therefore protocol-independent and affects all three date-based preconditions.

### Reproduction

From the repository root, start the existing cleartext fixture and compare one
malformed control, one real future date, and three nonexistent dates. This
leaves tracked files unchanged.

```sh
set -e
logdir=$(mktemp -d /tmp/linnea-audit-149.XXXXXX)
./bin/linnea --config test/configs/listen.json >"$logdir/server.log" 2>&1 &
pid=$!
cleanup() { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
trap cleanup EXIT
sleep 0.5

for value in \
  'not-a-date' \
  'Sun, 28 Feb 2099 00:00:00 GMT' \
  'Sun, 29 Feb 2099 00:00:00 GMT' \
  'Sun, 30 Feb 2099 00:00:00 GMT' \
  'Sun, 31 Feb 2099 00:00:00 GMT'
do
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 \
    -H "If-Modified-Since: $value" \
    http://127.0.0.1:61080/hello.txt)
  printf '%s  %s\n' "$code" "$value"
done
```

Observed on `1e28409`:

```text
200  not-a-date
304  Sun, 28 Feb 2099 00:00:00 GMT
304  Sun, 29 Feb 2099 00:00:00 GMT
304  Sun, 30 Feb 2099 00:00:00 GMT
304  Sun, 31 Feb 2099 00:00:00 GMT
```

The `not-a-date` control demonstrates the intended safe behavior: an
unparseable conditional date is ignored and the complete 200 response is sent.
28 February is the positive control showing that a real future date produces
304. The last three values name days that do not exist in February 2099 and
should follow the malformed control, not the valid date.

### Independent oracle

nginx 1.30.4 was run over the same file with `if_modified_since before`, so its
valid-date comparison has the same before-or-equal semantics as Linnea. Python
3's `email.utils.parsedate_to_datetime` was also asked to parse the four date
values.

| value | Linnea `1e28409` | nginx 1.30.4 | Python 3 |
|---|---:|---:|---|
| 28 February 2099 | 304 | 304 | accepted |
| 29 February 2099 | 304 | 200 | rejected |
| 30 February 2099 | 304 | 200 | rejected |
| 31 February 2099 | 304 | 200 | rejected |

Both independent parsers distinguish the real date from the impossible ones;
Linnea alone gives all four the same conditional meaning.

### Impact

A malformed `If-Modified-Since` can cause a false 304, telling a client or
cache to reuse a stored representation when the field should have been ignored
and a full response sent. The same normalization can produce a false 412 for
`If-Unmodified-Since`. An impossible date that normalizes to a file's exact
mtime can also pass `If-Range` and produce a 206 where the safe result is a
complete 200. This is cache and precondition correctness rather than a direct
confidentiality or memory-safety issue.

### Recommended fix

After resolving the month and four-digit year, validate the day against that
month's length, including the Gregorian leap rule (divisible by 4, except
century years unless divisible by 400), before calling
`linnea_time_days_from_civil`. Apply the check after obsolete date forms are
normalized so all three accepted HTTP-date syntaxes share it.

Add paired parser and end-to-end controls: 28 February 2099 and 29 February
2000 must parse; 29 February 2099, 29 February 2100, 30 February, and 31 April
must be ignored as invalid. Exercise at least `If-Modified-Since` and
`If-Range`, with a valid future date still producing 304 and arbitrary malformed
text still producing 200.

### Existing controls run

The paired HTTP/1 setup, static-serving, semantics, and teardown files completed
with **258 passed, 0 failed, 0 skipped**. This was a named-file partial run, not
a full shard. Its valid date, malformed-text, obsolete-format, conditional, and
range controls all pass; none crosses a month-length or leap-year boundary.

## Resolution (fix pass)

**Finding 1: FIXED.** The report reproduces: the original binary returned 304
for every impossible future date in the report. nginx 1.30.4, configured with
`if_modified_since before`, returned 200 for those values while retaining 304
for the valid 28 February control. RFC 9110 5.6.7 gives HTTP-date components
the semantics defined by RFC 5322 3.3, which requires a day of month to exist
in the named month and year; RFC 9110 13.1.3 requires an invalid
If-Modified-Since to be ignored.

`linnea_time_parse_http_date` now validates a month-specific maximum before it
calls `linnea_time_days_from_civil`: 30-day months, February, and the Gregorian
divisible-by-4 / century / divisible-by-400 leap rule are handled in one shared
gate. The gate runs after RFC 850 and asctime values have been normalized to the
IMF-shaped representation, so HTTP/1, HTTP/2, HTTP/3, and date-form If-Range
all receive the same verdict.

`test/tls/http_date_formats.py` now supplies paired end-to-end controls across
all three accepted syntaxes. Valid future leap days (IMF and asctime 2400;
RFC 850 2068) still return 304. Non-leap 29 February and 31 April return 200,
as does arbitrary malformed text. The added checks were run against the
pre-fix binary first and failed exactly four cases:

```text
FAIL IMF non-leap February 29: 304, want 200
FAIL IMF April 31: 304, want 200
FAIL RFC 850 April 31: 304, want 200
FAIL asctime April 31: 304, want 200
```

After the fix, the same test passed all 16 checks.

### What was run

- `./test/shards/run.sh base/10-config.sh` before the parser change — **47
  passed, 0 failed**.
- `make -j2` — rebuilt successfully.
- `test/tls/http_date_formats.py 61080` against a temporary cleartext fixture,
  before and after the change — four new checks failed before; all passed after.
- `./test/shards/run.sh h1/00-setup.sh h1/20-serving.sh
  h1/25-http-semantics.sh h1/30-proxying.sh h1/50-teardown.sh tls/20-e2e.sh
  tls/40-http2.sh tls/50-e2e-teardown.sh` — **445 passed, 0 failed, 8 skipped**.
  This is a named-file partial run, not the full suite.
