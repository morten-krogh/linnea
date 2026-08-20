# Audit Report 27

Audited at `692eb06`, 2026-08-20.

## Review result

Audit-report-26 is **fixed** in `95dee8a`: `.relay_next` now checks the carried
`resp_chunk_state` and finishes immediately when it is `LINNEA_CHUNK_DONE`.
The completion check occurs before arming another upstream receive, so a
keep-alive backend can no longer hold a completed chunked response until the
proxy timeout. The follow-up `692eb06` also restores the access-log line that
was previously lost on that timeout path.

I found no additional source-verifiable security or protocol defect in the
reviewed relay path. In particular, the split-read validator remains in
`linnea_uring.asm` and still carries `resp_chunk_state` across every read; the
terminal-chunk check is now applied before the next read is armed.

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Confirmed independently (2026-08-20)

Agreed, and checked rather than taken: the two `LINNEA_CHUNK_VALIDATE` call
sites are the head-adjacent leftover (`linnea_http.asm:4536`) and the
steady-state relay (`linnea_uring.asm:2501`), and `resp_chunk_state` is asked at
both the pre-read branch (`:2544`) and the EOF branch (`:2477`). The build is
warning-free, which is this tree's tripwire for a truncated immediate since
report 22.

State at this commit, since a no-finding audit is the moment to say where things
actually stand rather than where the reports imply they are:

* Full suite **777 passed, 0 failed** at `95dee8a`; `692eb06` changed only the
  report file.
* Seven commits are on `master` and **none of them are on production**, which is
  still running the report-23 build (`/usr/local/bin/linnea` md5 `160f9c5…`,
  local `45db6b8…`). Reports 24, 25 and 26, the access-log version fix, and
  their fixtures all wait on a deploy.
* One thing deliberately not done, recorded so it is not mistaken for an
  oversight: a chunked response is self-delimiting, so the client connection
  could be kept alive once the relay finishes at the terminal chunk.
  `.until_eof` still clears `keep_alive` for every chunked proxied response.

## Verification

No executable tests were run: this report makes no source change. The review
traced the fixed completion branch and the steady-state validation call against
the current source.

## Conclusion

The report-26 finding is closed, and this audit found no new open finding.
