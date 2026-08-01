#!/usr/bin/env python3
"""All three HTTP-date formats must parse (RFC 9110 5.6.7).

    "A recipient that parses a timestamp value in an HTTP field MUST accept all
     three HTTP-date formats."

Only IMF-fixdate was accepted. The other two parsed as invalid, and an invalid
date means the condition is ignored — so a client sending an obsolete format got
the whole body back instead of the 304 its cached copy had earned. Silent, and
only visible as wasted bandwidth.

    IMF-fixdate  Sun, 06 Nov 1994 08:49:37 GMT
    RFC 850      Sunday, 06-Nov-94 08:49:37 GMT
    asctime      Sun Nov  6 08:49:37 1994

Each format is sent twice: once with the file's own mtime, which must give 304,
and once with a date a minute EARLIER, which must give 200. The second half is
what proves the value was actually read — a parser that returned a constant, or
one that treated any parsable date as "not modified", would pass the first check
alone.

usage: http_date_formats.py <port>
"""
import socket
import sys
from datetime import datetime, timedelta, timezone

port = int(sys.argv[1])
HOST = b"one.test"
PATH = b"/hello.txt"

WDAY = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
WDAY_FULL = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
             "Saturday", "Sunday"]
MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
       "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def imf(d):
    return (f"{WDAY[d.weekday()]}, {d.day:02d} {MON[d.month - 1]} {d.year:04d} "
            f"{d.hour:02d}:{d.minute:02d}:{d.second:02d} GMT")


def rfc850(d):
    return (f"{WDAY_FULL[d.weekday()]}, {d.day:02d}-{MON[d.month - 1]}-"
            f"{d.year % 100:02d} {d.hour:02d}:{d.minute:02d}:{d.second:02d} GMT")


def asctime(d):
    return (f"{WDAY[d.weekday()]} {MON[d.month - 1]} {d.day:2d} "
            f"{d.hour:02d}:{d.minute:02d}:{d.second:02d} {d.year:04d}")


def request(extra=b""):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(3)
    s.sendall(b"GET " + PATH + b" HTTP/1.1\r\nHost: " + HOST + b"\r\n"
              + extra + b"Connection: close\r\n\r\n")
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except socket.timeout:
        pass
    s.close()
    head = out.split(b"\r\n\r\n")[0].decode("latin1", "replace")
    status = int(head.split()[1])
    last_mod = None
    for line in head.split("\r\n")[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "last-modified":
            last_mod = value.strip()
    return status, last_mod


status, last_mod = request()
if status != 200 or not last_mod:
    print(f"FAIL baseline GET was {status} with Last-Modified {last_mod!r}")
    sys.exit(1)

mtime = datetime.strptime(last_mod, "%a, %d %b %Y %H:%M:%S GMT").replace(
    tzinfo=timezone.utc)
earlier = mtime - timedelta(minutes=1)

fails = 0
for name, fmt in (("IMF-fixdate", imf), ("RFC 850", rfc850), ("asctime", asctime)):
    at, before = fmt(mtime), fmt(earlier)

    status, _ = request(f"If-Modified-Since: {at}\r\n".encode())
    if status == 304:
        print(f"ok   {name}: the file's own mtime gives 304")
    else:
        print(f"FAIL {name}: mtime gave {status}, want 304 — the date did not "
              f"parse, so the condition was ignored ({at})")
        fails += 1

    status, _ = request(f"If-Modified-Since: {before}\r\n".encode())
    if status == 200:
        print(f"ok   {name}: a minute earlier gives 200")
    else:
        print(f"FAIL {name}: a date BEFORE the mtime gave {status}, want 200 — "
              f"the value is not being read ({before})")
        fails += 1

# The two-digit year needs the windowing rule of 5.6.7: a year "more than 50
# years in the future" is the most recent PAST year with those digits. The first
# cut of this windowed on the day of the month instead, so "06-Nov-94" became
# 2094 — a future date, which turns an If-Modified-Since for 1994 into a 304.
# Both halves of the window are checked, and against the IMF spelling of the same
# instant so the comparison is to the parser that was already right.
for label, obsolete, modern in (
        ("a 1990s year", "Sunday, 06-Nov-94 08:49:37 GMT",
         "Sun, 06 Nov 1994 08:49:37 GMT"),
        ("a recent year", "Monday, 06-Nov-06 08:49:37 GMT",
         "Mon, 06 Nov 2006 08:49:37 GMT")):
    a, _ = request(f"If-Modified-Since: {obsolete}\r\n".encode())
    b, _ = request(f"If-Modified-Since: {modern}\r\n".encode())
    if a == b:
        print(f"ok   {label}: the two-digit form agrees with the four-digit one "
              f"({a})")
    else:
        print(f"FAIL {label}: two-digit gave {a}, four-digit {b} — the century "
              f"window is wrong ({obsolete})")
        fails += 1

# an unparsable date is ignored, not an error (5.6.7 / 13.1.3)
status, _ = request(b"If-Modified-Since: not a date at all\r\n")
if status == 200:
    print("ok   an unparsable date is ignored and the resource served")
else:
    print(f"FAIL an unparsable date gave {status}, want 200")
    fails += 1

sys.exit(1 if fails else 0)
