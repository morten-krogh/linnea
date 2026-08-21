# How linnea is built with AI

Linnea is written mostly by **Claude, Anthropic's AI**, with some contributions
and audits by **Codex, OpenAI's coding agent**, all under the direction and
review of its author, **Morten Krogh**. This document is an honest account of
what that means, how the process actually works, what it is good and bad at, and
why we think a from-scratch assembly web server is a fair demonstration of it.

It is not a marketing page. If anything it errs the other way: the point of
linnea is undermined, not served, by overstating what AI-assisted development
can do.

## What "written by AI" means here

The division of labour is roughly this:

- **The author, Morten Krogh,** sets goals, decides what to build and what not
  to, reviews changes, makes the release and deployment calls, and owns the
  judgement about what is acceptable to ship. Nearly every design decision is a
  conversation.
- **The AI agents** read the existing code, write the assembly, write the tests,
  run and debug against real binaries, perform the security and conformance
  audits, and write the documentation — including this file. Most of that is
  **Claude**; some contributions and audits are by **Codex**.

Commits are co-authored by the agent that wrote them, and that attribution is
accurate: the assembly, the test harnesses, the audit findings, and the prose
are predominantly machine-written, then human-reviewed. This is a
human-directed project implemented by AI, not an autonomous one.

More than one agent is deliberate. A second model auditing the first's work is a
useful check — a reviewer that does not share the author's blind spots — and it
is a small version of where the project is headed: **other AI agents, and human
contributors, are welcome**. Nothing about linnea assumes a single model or a
single author. See [`../CONTRIBUTING.md`](../CONTRIBUTING.md).

## What the process actually looks like

The working loop is closer to a rigorous engineering practice than to
"generate some code." A few things that define it:

- **Audits, repeatedly.** Linnea has been through multiple structured
  security and RFC-conformance audits — h1/h2/h3, QUIC, TLS — most of them
  AI-driven, each producing a numbered report of findings that are then fixed
  and verified one at a time. Whole classes of defect were found this way.
- **Verify against the running thing, not the source.** A reading is treated as
  a hypothesis, not a conclusion. A finding is demonstrated with a probe against
  a real binary before it is called a bug; a fix is proven by building the
  *old* binary too and running both at once, showing the new check fails on one
  and passes on the other. "It looks right" is not evidence.
- **A standalone compliance prober.** `linnea-probe` is a dependency-free
  HTTP/1, HTTP/2 and HTTP/3 conformance prober, itself written in assembly, that
  can be pointed at any server. It is used to test linnea against an independent
  implementation of the same protocols.
- **An extensive test suite that gates deploys.** Hundreds of checks across the
  three protocols, TLS, QUIC and the proxy, run before anything ships.
- **A written memory of what was learned.** Disproven theories, recurring defect
  shapes, and the reasons behind decisions are recorded so they are not
  rediscovered the hard way — or repeated.

## What AI-assisted development is good at here

- **Breadth and stamina.** Implementing HTTP/1.1, HTTP/2, HTTP/3, QUIC and TLS
  1.3 from scratch in assembly is an enormous amount of exacting, tedious work.
  The AI does not tire of it, and it will write the fifteenth verification test
  as carefully as the first.
- **Thoroughness on demand.** Sweeping every call site for a defect class,
  re-auditing a subsystem, or writing an adversarial test for a specific race is
  cheap enough to do routinely rather than only when something breaks.
- **Consistency.** Conventions, error-handling shapes, and buffer-sizing
  discipline stay uniform across a large codebase because the same author holds
  them everywhere.

## What it is bad at, and the risks

This is the part that matters most, and we state it plainly.

- **Assembly has no safety net.** No memory safety, no type system, nothing that
  crashes to tell you a fix did nothing or that a bound is wrong. A plausible,
  confident, wrong change is entirely possible, and nothing about the language
  will catch it. The discipline above exists precisely because the substrate
  offers no guardrails.
- **Green tests do not prove correctness.** The most dangerous defects here have
  been *omissions* — a missing check, a case never exercised — which by
  definition no passing test detects. The sharpest example: a required check
  that the computed X25519 shared secret was not all-zero was **missing on both
  TLS handshake paths**, and it survived a 71-finding audit before a later
  review caught it. Thousands of green cryptographic test vectors could not have
  found it, because they were testing the code that *was* there.
- **Fixes that land on one of several copies.** A repeated shape: a bug exists
  in three places (an HTTP/1, HTTP/2 and HTTP/3 twin), the fix lands on one, and
  the other two survive looking fixed. Every fix now triggers a search for its
  twins.
- **Its own cryptography.** Linnea's crypto is not a hardened, decades-audited
  library. That it is self-contained is a genuine property — no inherited
  dependency vulnerabilities — but it is also far less battle-tested than
  BoringSSL, and it should be weighed accordingly. See
  [`security.md`](security.md).

None of these are hypothetical; each has bitten at least once and is written
down because of it. The honest summary is that AI-assisted development produced
this codebase to a high standard **with a human in the loop and a heavy
verification discipline** — and would not have produced something trustworthy
without them.

## The honesty policy

Because the failure modes above are real, the project holds itself to a few
rules that this document tries to model:

- **State severity you can defend.** When a finding is real but not exploitable,
  say both, and say which.
- **Write down what was ruled out.** When a cause cannot be established, the
  disproven theories are recorded rather than a confident guess left in their
  place — repeating a confident wrong guess is exactly what that costs.
- **Say "not established" when it is not.** A result that was not actually
  measured is reported as unverified, not as a success.

## What this does and does not demonstrate

It demonstrates that, with a capable model, a human director, and a disciplined
verification loop, AI-assisted engineering can build real, low-level systems
software — not a toy — and keep it correct enough to run in production.

It does **not** demonstrate that AI-written code is safe by default, that the
tests speak for themselves, or that hand-rolled AI-written cryptography deserves
the trust you would extend to a mature library. Those would be the wrong lessons
to take, and taking them is the risk the project is most careful about.

## Contributing, with AI

Because this is how linnea is written, AI-assisted and AI-reviewed contributions
are explicitly welcome — held to the same bar: demonstrated against a real
binary, tested, and honest about what was and was not verified. See
[`../CONTRIBUTING.md`](../CONTRIBUTING.md).
