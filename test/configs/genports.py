#!/usr/bin/env python3
"""Write the suite's configs into test/configs/run/ with their ports rebased.

NB: every config key naming a path a server READS or WRITES has to appear in
the rewrites at the bottom, or a fixture using it keeps a repo-relative path
while the server runs with the run directory as its CWD. error_log joined that
list the day it was added, after the suite stopped with "cannot open log file"
-- loudly, which is the only reason it took a minute rather than an afternoon.

Every port the suite binds lives in 61000..61999, and each is rewritten to
LINNEA_TEST_PORT_BASE + (port - 61000). One base per run means two suites can
run at once without fighting over a single number — which fixed ports cannot
do, however carefully they are chosen. The default base is 61000, so an
ordinary run gets exactly the numbers the templates already carry and nothing
observable changes.

Ports OUTSIDE that window are deliberate and untouched: 8080 and 70000 are
there to be rejected, 3000 belongs to a proxy address that is never dialled,
and 0 means "let the kernel choose" (see docs/config.md).

The rewrite is TEXTUAL, not a JSON round trip. Some of these files are not
valid JSON on purpose — truncated.json is cut off mid-document and escape.json
carries an escape sequence the parser must refuse — so parsing and re-emitting
would quietly repair the very thing they test. A regex over the text preserves
every byte that is not a port, including the formatting the parse-error tests
count columns against.

The same pass redirects everything a running server WRITES or SERVES into the
run's own directory: its log, its document root, and the port_file it reports
through. Two runs would otherwise grep one another's log lines and regenerate
one another's fixtures — the document root is not read-only, the suite builds
files in it and deletes them again. Certificates and keys are left alone: they
are read-only inputs and sharing them is free.

Usage: genports.py <base> <outdir> [rundir]
"""
import os
import re
import shutil
import sys

BASE_DEFAULT = 61000
LOW, HIGH = 61000, 62000

base = int(sys.argv[1]) if len(sys.argv) > 1 else BASE_DEFAULT
outdir = sys.argv[2] if len(sys.argv) > 2 else "test/configs/run"
rundir = sys.argv[3] if len(sys.argv) > 3 else None
srcdir = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(srcdir))   # the repo root

if base + (HIGH - LOW) > 65535:
    sys.exit("port base %d would push the suite's ports past 65535" % base)

# Fixtures that ask the KERNEL for their port. Single-server only: two servers
# that both say 0 get two different ports, which is precisely what a shared
# listener must not have. The port_file is how the harness learns the answer.
PORT_ZERO = ['limits.json', 'spill-dir.json', 'tls-h2.json', 'tls-h3-big.json', 'tls-h3-bigcert.json', 'tls-h3-canned.json', 'tls-h3-cancel.json', 'tls-h3-maxhdr.json', 'tls-h3-drain.json', 'tls-h3-fuzz.json', 'tls-h3-proxy.json', 'tls-h3-spillfail.json', 'tls-h3-v6.json', 'tls-h3.json', 'tls-slowbody.json', 'tls-slowhead.json', 'tls.json']

port_re = re.compile(r"\b(6[01][0-9]{3})\b")


def rebase(m):
    p = int(m.group(1))
    return str(base + (p - LOW)) if LOW <= p < HIGH else m.group(1)


os.makedirs(outdir, exist_ok=True)
n = 0
for name in sorted(os.listdir(srcdir)):
    if not name.endswith(".json"):
        continue
    src = os.path.join(srcdir, name)
    dst = os.path.join(outdir, name)
    text = open(src, "r", errors="surrogateescape").read()
    out = port_re.sub(rebase, text) if base != LOW else text
    if name in PORT_ZERO and rundir:
        # single server, so exactly one "port" key: let the kernel choose, and
        # say where to report what it chose
        out = re.sub(r'("port": )\d+', r'\g<1>0', out, count=1)
        # written template-relative ("test/NAME.ports") so the generic rundir
        # rewrite below moves it exactly once -- prefixing it here as well gave
        # test/run-61000/run-61000/NAME.ports
        out = re.sub(r'("log": "[^"]*",)',
                     r'\1\n  "port_file": "test/%s.ports",' % name[:-5],
                     out, count=1)
    if rundir:
        # what the server writes or serves moves into the run's own directory
        out = re.sub(r'("log": ")test/([^"]*)"', r'\1%s/\2"' % rundir, out)
        out = re.sub(r'("error_log": ")test/([^"]*)"', r'\1%s/\2"' % rundir, out)
        out = re.sub(r'("port_file": ")test/([^"]*)"', r'\1%s/\2"' % rundir, out)
        out = re.sub(r'("root": ")test/www', r'\1%s/www' % rundir, out)
        # Every path a server reads or writes becomes ABSOLUTE, because the
        # server is then started with its own run directory as its working
        # directory -- and that is the only way to give each run its own
        # "linnea-qdbg". The QUIC trace trigger is a filename the server
        # resolves against its CWD (linnea_quic_debug.asm), so two runs sharing
        # a working directory share the switch: one run's persistent-congestion
        # test turned per-connection tracing on in the OTHER run's servers,
        # which is extra work and log I/O on every packet, and removing it
        # again pulled the trace out from under a concurrent test. Measured: 0
        # qdbg lines before a neighbouring run touched the file, 4 after.
    out = re.sub(r'("(?:log|error_log|root|cert|key|spill_dir|port_file)": ")(test/)',
                 r'\1%s/\2' % REPO, out)
    open(dst, "w", errors="surrogateescape").write(out)
    n += 1

# the certs and roots the configs name are relative to the repo root, so the
# generated directory needs nothing else copied into it
print("%d configs written to %s (base %d)" % (n, outdir, base))
