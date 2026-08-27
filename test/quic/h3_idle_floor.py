#!/usr/bin/env python3
# A peer advertising a SHORT max_idle_timeout must not lose its connection while
# it could still be probing. RFC 9000 10.1: "To avoid excessively small idle
# timeout periods, endpoints MUST increase the idle timeout period to be at
# least three times the current Probe Timeout (PTO). This allows for multiple
# PTOs to expire, and therefore multiple probes to be sent and lost, prior to
# idle timeout."
#
# The floor used to be a flat one second, which on a connection with no RTT
# sample is well under three PTOs (~1022ms each, so ~3.07s) -- audit-report-90
# arrived arguing the opposite, that the ROUNDING UP of the peer's milliseconds
# kept slots too long, and the floor is what actually matters: it is larger than
# any rounding, and it was too small.
#
# The client advertises 1s, goes quiet for 2s, then asks again. aioquic's own
# idle timer is never driven -- handle_timer is not called during the wait -- so
# what is measured is the SERVER's reclamation, not the client's.
#
# Usage: h3_idle_floor.py <port>.  Prints ok/FAIL.
import socket, ssl, sys, time
import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived as H3Headers
PORT = int(sys.argv[1]); QUIET = 2.0
def vlq(n):
    return bytes([n]) if n < 64 else (0x4000 | n).to_bytes(2, "big")
cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE; cfg.server_name = "localhost"
cfg.idle_timeout = 1.0                       # advertise max_idle_timeout = 1000ms
conn = QuicConnection(configuration=cfg); vt=[0.0]
def clk():
    vt[0]+=0.001; return vt[0]
conn.connect(("127.0.0.1",PORT),now=clk())
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(0.3)
def flush():
    for d,_ in conn.datagrams_to_send(now=clk()): s.sendto(d,("127.0.0.1",PORT))
flush(); dl=time.time()+8
while not conn._handshake_confirmed and time.time()<dl:
    try:
        r,_=s.recvfrom(65535); conn.receive_datagram(r,("127.0.0.1",PORT),now=clk())
    except socket.timeout: conn.handle_timer(now=clk())
    flush()
assert conn._handshake_confirmed, "handshake failed"
h3 = H3Connection(conn)
def request(path):
    enc=pylsqpack.Encoder(); enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _,f=enc.encode(0,[(b":method",b"GET"),(b":scheme",b"https"),
                      (b":authority",b"localhost"),(b":path",path)])
    sid=conn.get_next_available_stream_id()
    conn.send_stream_data(sid, vlq(1)+vlq(len(f))+f, end_stream=True); flush()
    st=None; dl=time.time()+3
    while st is None and time.time()<dl:
        try:
            r,_=s.recvfrom(65535); conn.receive_datagram(r,("127.0.0.1",PORT),now=clk())
            for qe in iter(conn.next_event,None):
                for ev in h3.handle_event(qe):
                    if isinstance(ev,H3Headers) and ev.stream_id==sid:
                        for k,v in ev.headers:
                            if k==b":status": st=v.decode()
        except socket.timeout: pass
        for d,_ in conn.datagrams_to_send(now=clk()): s.sendto(d,("127.0.0.1",PORT))
    return st
first = request(b"/hello.txt")
time.sleep(QUIET)                            # silent; no client timers driven
again = request(b"/hello.txt")
if first == "200" and again == "200":
    print("ok   a 1s idle timeout still clears three PTOs (%s then %s)" % (first, again))
    sys.exit(0)
print("FAIL first=%s after %.1fs quiet=%s -- the slot went before three PTOs"
      % (first, QUIET, again))
sys.exit(1)
