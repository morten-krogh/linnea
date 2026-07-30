#!/usr/bin/env python3
"""The HPACK desync: a block we reject must still leave our dynamic table
matching the peer's, or a LATER request decodes against the wrong entries.

Case A drives it end to end. On one connection:
  1. a request whose block inserts 'a-one: 1' (incremental) then carries a
     MALFORMED field, so the stream is rejected -- and a further insert
     'a-two: 2' AFTER the bad field, which the encoder's table gets regardless;
  2. a good request referencing dynamic index 62 (the newest entry).
Index 62 must resolve to 'a-two'. If the decoder stopped at the bad field it
holds only 'a-one', so 62 resolves to that -- a header the client never sent.
"""
import socket, ssl, struct, sys
ca, port = sys.argv[1], int(sys.argv[2])
def fr(t,fl,sid,p=b""): return struct.pack(">I",len(p))[1:]+bytes([t,fl])+struct.pack(">I",sid)+p
def lit_idx(n, v):           # literal, incremental indexing, literal name
    return b"\x40"+bytes([len(n)])+n+bytes([len(v)])+v
def lit_plain(n, v):         # literal, no indexing
    return b"\x00"+bytes([len(n)])+n+bytes([len(v)])+v
def idx(i):                  # indexed field line
    return bytes([0x80 | i])
def rd(s):
    hd=b""
    while len(hd)<9:
        d=s.recv(9-len(hd))
        if not d: return None
        hd+=d
    ln=int.from_bytes(hd[:3],"big"); p=b""
    while len(p)<ln:
        d=s.recv(ln-len(p))
        if not d: break
        p+=d
    return hd[3],hd[4],int.from_bytes(hd[5:9],"big")&0x7fffffff,p

ctx=ssl.create_default_context(cafile=ca); ctx.check_hostname=False
ctx.set_alpn_protocols(["h2"])
s=ctx.wrap_socket(socket.create_connection(("127.0.0.1",port),timeout=6),server_hostname="localhost")
s.settimeout(5)
s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"+fr(4,0,0))

M=lit_plain(b":method",b"GET"); S=lit_plain(b":scheme",b"https")
A=lit_plain(b":authority",b"localhost"); P=lit_plain(b":path",b"/hello.txt")
# stream 1: insert 'range' FIRST, then a malformed field (uppercase name), then
# insert 'a-two' AFTER it. The two entries are chosen so that resolving index 62
# to the wrong one is VISIBLE: 'range: bytes=0-4' turns the response into a 206,
# 'a-two' is ignored and leaves a 200.
blk1 = M+S+A+P + lit_idx(b"range",b"bytes=0-4") + lit_plain(b"X-Bad",b"v") + lit_idx(b"a-two",b"2")
s.sendall(fr(1,0x05,1,blk1))
v1="no reply"
for _ in range(10):
    r=rd(s)
    if r is None: v1="closed"; break
    t,fl,sid,p=r
    if t==7: v1="GOAWAY"; break
    if t==3 and sid==1: v1="RST_STREAM err=%d"%int.from_bytes(p[:4],"big"); break
print(f"  stream 1 (insert, bad field, insert) -> {v1}")
if v1.startswith("GOAWAY") or v1=="closed":
    print("  connection gone; cannot test the follow-up"); s.close(); sys.exit(1)

# stream 3: reference dynamic index 62 = the NEWEST entry the peer inserted.
# The peer's newest is 'a-two'. Ours must be too.
blk2 = M+S+A+P + idx(62)
s.sendall(fr(1,0x05,3,blk2))
v2="no reply"
for _ in range(10):
    r=rd(s)
    if r is None: v2="closed"; break
    t,fl,sid,p=r
    if t==7: v2="GOAWAY err=%d"%int.from_bytes(p[4:8],"big"); break
    if t==3 and sid==3: v2="RST_STREAM err=%d"%int.from_bytes(p[:4],"big"); break
    if t==1 and sid==3:
        v2 = "served " + next((c.decode() for c in (b"200",b"206",b"404") if c in p), "?")
        break
print(f"  stream 3 (references dynamic index 62) -> {v2}")
s.close()
# In sync, 62 is the peer's newest entry, 'a-two', which changes nothing: 200.
# Desynced, our newest is still 'range', so the SAME request comes back 206 --
# a header the client never sent for this request, applied to it.
if v2 == "served 200":
    print("SYNC OK: index 62 resolved to the entry the peer inserted last")
    sys.exit(0)
if v2 == "served 206":
    print("DESYNC: index 62 resolved to 'range' -- our table is behind the peer's")
    sys.exit(2)
print("unexpected: " + v2)
sys.exit(2)
