#!/usr/bin/env python3
"""Hammer the server with concurrent connections across a hot upgrade.

`upgrade refuses no new request` issues one curl at a time, ~30/s, and caught
the drain's resets about once in a dozen SUITE runs -- too rare to tell a fix
from luck. Many connections in flight at the handover fill the listener's
accept queue, so anything the drain does to that queue shows up at once:

    drain refuses raced-in connections   9 of 10 rounds reset something
    + serves them (Q177)                 2 of 10
    + sweeps the accept queue (Q178)     0 of 10, ~386k attempts

Every attempt is classified, so a failure says which mechanism bit:
  reset    ECONNRESET -- taken and then thrown away, or purged from the queue
  refused  ECONNREFUSED -- no listener at all, i.e. the group was left empty
  empty    connected, request sent, closed with no reply

Usage: upgrade_burst.py <master-pid> [port]
"""
import os
import signal
import socket
import sys
import threading
import time

REQ = b"GET /hello.txt HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n"
WORKERS = 40
DURATION = 2.5
UPGRADE_AT = 1.0

counts = {"ok": 0, "reset": 0, "refused": 0, "empty": 0, "other": 0}
lock = threading.Lock()
stop = threading.Event()


def bump(key):
    with lock:
        counts[key] += 1


def hammer(port):
    while not stop.is_set():
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
        except ConnectionRefusedError:
            bump("refused")
            continue
        except OSError:
            bump("other")
            continue
        try:
            s.settimeout(5)
            s.sendall(REQ)
            data = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
            if data.startswith(b"HTTP/1.1 200"):
                bump("ok")
            elif not data:
                bump("empty")
            else:
                bump("other")
        except ConnectionResetError:
            bump("reset")
        except socket.timeout:
            bump("other")
        except OSError as e:
            bump("reset" if e.errno == 104 else "other")
        finally:
            s.close()


def main():
    if len(sys.argv) < 2:
        print("usage: upgrade_burst.py <master-pid> [port]", file=sys.stderr)
        return 2
    master = int(sys.argv[1])
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 47080

    threads = [threading.Thread(target=hammer, args=(port,), daemon=True)
               for _ in range(WORKERS)]
    for t in threads:
        t.start()
    time.sleep(UPGRADE_AT)
    os.kill(master, signal.SIGUSR2)
    time.sleep(DURATION - UPGRADE_AT)
    stop.set()
    for t in threads:
        t.join(timeout=8)

    total = sum(counts.values())
    lost = counts["reset"] + counts["refused"] + counts["empty"]
    print(f"{total} attempts, {lost} lost "
          f"(reset={counts['reset']} refused={counts['refused']} "
          f"empty={counts['empty']} other={counts['other']})")
    if total < 1000:
        print("too few attempts to mean anything", file=sys.stderr)
        return 2
    return 1 if lost else 0


if __name__ == "__main__":
    sys.exit(main())
