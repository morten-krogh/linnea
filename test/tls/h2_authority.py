#!/usr/bin/env python3
# Q124: HTTP/2 request rules around the authority (RFC 9113 8.3, 8.3.1).
# :authority is h2's Host, and none of its rules were enforced: a duplicate
# :authority took the LAST value (with two vhosts that picked a different
# document root than the first — the smuggling shape Q123 closed for h1), a
# Host contradicting :authority was ignored rather than refused, and a request
# with no authority at all was served. Each violation must now fail THAT
# STREAM (RFC 9113 8.1.1 — the field block decoded, so the connection and its
# HPACK state are fine) while the connection keeps serving.
# Usage: h2_authority.py <cafile> <port>
import socket, ssl, struct, sys
ca, port = sys.argv[1], int(sys.argv[2])
def fr(t,fl,sid,p=b""): return struct.pack(">I",len(p))[1:]+bytes([t,fl])+struct.pack(">I",sid)+p
def h(n,v): return b"\x00"+bytes([len(n)])+n+bytes([len(v)])+v
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
def probe(name, fields):
    ctx=ssl.create_default_context(cafile=ca); ctx.check_hostname=False
    ctx.set_alpn_protocols(["h2"])
    s=ctx.wrap_socket(socket.create_connection(("127.0.0.1",port),timeout=5),server_hostname="localhost")
    s.settimeout(4)
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"+fr(4,0,0))
    s.sendall(fr(1,0x05,1,fields))
    verdict=None
    try:
        for _ in range(12):
            r=rd(s)
            if r is None: verdict="connection closed"; break
            t,fl,sid,p=r
            if t==3 and sid==1: verdict="RST_STREAM(err=%d)"%int.from_bytes(p[:4],"big"); break
            if t==7: verdict="GOAWAY (connection error)"; break
            if t==1 and sid==1:
                for c in (b"200",b"400",b"404",b"421",b"431"): 
                    if c in p: verdict="served %s"%c.decode(); break
                if verdict: break
    except Exception as e:
        verdict=verdict or "timeout/%s"%type(e).__name__
    # does the connection still serve?
    alive="-"
    if verdict and verdict.startswith("RST"):
        try:
            s.sendall(fr(1,0x05,3,h(b":method",b"GET")+h(b":scheme",b"https")+h(b":authority",b"localhost")+h(b":path",b"/hello.txt")))
            for _ in range(8):
                r=rd(s)
                if r is None: alive="no"; break
                if r[0]==1 and r[2]==3 and b"200" in r[3]: alive="yes"; break
        except Exception: alive="no"
    s.close()
    return verdict, alive
A=h(b":authority",b"localhost"); M=h(b":method",b"GET"); S=h(b":scheme",b"https"); P=h(b":path",b"/hello.txt")

# Each case says what the stream must end as: "200" for a request that is fine,
# "RST" for one that breaks a rule. A rejected stream must also leave the
# connection serving — the field block decoded, so the HPACK state is intact and
# RFC 9113 8.1.1 makes this a stream error, not a connection one.
CASES = [
    ("baseline", M+S+A+P, "200"),
    ("no :authority, no Host", M+S+P, "RST"),
    ("Host only (legal h1->h2 translation)", M+S+P+h(b"host",b"localhost"), "200"),
    ("duplicate :authority", M+S+A+h(b":authority",b"evil.test")+P, "RST"),
    (":authority + conflicting Host", M+S+A+P+h(b"host",b"evil.test"), "RST"),
    (":authority + agreeing Host", M+S+A+P+h(b"host",b"localhost"), "200"),
    ("duplicate :path", M+S+A+P+h(b":path",b"/secret"), "RST"),
    ("pseudo after regular field", M+S+h(b"accept",b"*/*")+A+P, "RST"),
    ("unknown pseudo-header", M+S+A+P+h(b":protocol",b"x"), "RST"),
    ("empty :authority", M+S+h(b":authority",b"")+P, "RST"),
    ("duplicate Host", M+S+P+h(b"host",b"localhost")+h(b"host",b"localhost"), "RST"),
    # a field name is a token, so it is never empty: an empty one used to pass
    # the name scan untouched and go upstream as a bare ": value" line
    ("empty field name", M+S+A+P+h(b"",b"x"), "RST"),
    # h1 cannot carry a control byte in the request line at all; here the target
    # is just a field value, so an ESC used to reach the access log
    ("control byte in :path", M+S+A+h(b":path",b"/hello\x1b.txt"), "RST"),
    ("space in :path", M+S+A+h(b":path",b"/hello .txt"), "RST"),
]

fails=0
for name, fields, want in CASES:
    verdict, alive = probe(name, fields)
    ok = (verdict == "served 200") if want == "200" else \
         (verdict is not None and verdict.startswith("RST") and alive == "yes")
    print(f"{'ok  ' if ok else 'FAIL'} {name}: {verdict} (alive={alive}), want {want}")
    fails += not ok
if fails:
    sys.exit(1)
