# Contributing to linnea

Contributions are welcome. Because linnea is written mostly by Claude with some
contributions and audits by Codex (see
[`docs/ai-development.md`](docs/ai-development.md)), **AI-assisted and
AI-reviewed contributions are explicitly encouraged** — and so are human ones,
and those from other AI agents. Nothing here assumes a single model or a single
author.

Whatever wrote a change, it is held to the same bar.

## The bar

Linnea is assembly with no memory safety and no type system, and it runs on the
public internet. So the standard is not "it looks right" — it is **demonstrated**:

- **Show it against a real binary.** A finding is proven with a probe against a
  running server, not argued from the source. A fix is proven by building the
  *old* binary too and running both — the new behaviour must be visible on one
  and not the other.
- **Test what you touched.** Add or extend a test that fails before your change
  and passes after. The full suite (`LINNEA_SUITE=full ./test/run_shards.sh`)
  must pass.
- **Keep the build warning-free.** A new assembler warning is a real signal here
  (a truncated immediate, a suspicious size); do not add one.
- **Fix every twin.** A rule usually lives in three places — the HTTP/1, HTTP/2
  and HTTP/3 paths. A fix that lands on one and leaves the others is the single
  most repeated defect in this codebase. Grep for the pattern, not the line.
- **Be honest about what you verified.** Say what was checked and what was not.
  "Not established" is a fine thing to write; a result you did not actually
  measure reported as success is not.

## Practicalities

- Read [`docs/building.md`](docs/building.md) to build and test, and
  [`docs/architecture.md`](docs/architecture.md) for how the pieces fit.
- Match the surrounding style: the codebase has consistent conventions for
  register use, error handling, and buffer sizing. New code should read like the
  code next to it, and comments should state constraints the code cannot show,
  not narrate it.
- Sizing is derived from documented maxima. If you add a buffer or a limit,
  derive its size from the largest input the configuration can produce, and
  bound every copy into it before the copy.
- Discuss anything large in an issue first. A new subsystem, a protocol feature,
  or a change to a documented contract is worth agreeing on before it is written.

## Attribution

Commits made by an AI agent are co-authored by that agent, and that is expected —
it is how the project is built and part of what it demonstrates. Please keep that
attribution accurate on your own contributions.

## Security

Do not report vulnerabilities in a pull request or a public issue. See
[`SECURITY.md`](SECURITY.md).
