#!/usr/bin/env python3
# Version Negotiation (RFC 9000 §6.1 / §17.2.1). A long-header packet with a version
# the server does not support must draw a Version Negotiation packet: a long header
# with version 0, the client's Source CID as the reply's Destination CID and vice
# versa, then the list of versions the server speaks (currently QUIC v1). This lets
# a client using an unsupported version retry with one we understand.
#
# Sends a raw bogus-version Initial-shaped packet (padded past the 1200-byte floor)
# and checks the reply. Usage: h3_version_negotiation_test.py <port>
import os, socket, struct, sys

PORT = int(sys.argv[1])
BOGUS = 0x1a2a3a4a
V1 = 0x00000001
dcid = os.urandom(8)
scid = os.urandom(8)

# long header: first byte (top bit set), version, DCID len+DCID, SCID len+SCID.
# Deliberately small and UNPADDED: version scanners and reachability probes send
# tiny packets, and the server must still answer them (the VN reply is ~31 bytes,
# so there is no amplification). A 1200-byte floor here silently drops such probes.
pkt = (bytes([0xc0]) + struct.pack(">I", BOGUS)
       + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3.0)
s.sendto(pkt, ("127.0.0.1", PORT))
try:
    reply, _ = s.recvfrom(65535)
except socket.timeout:
    print("FAIL: no Version Negotiation packet for an unsupported version")
    sys.exit(1)

# long header form
if not (reply[0] & 0x80):
    print(f"FAIL: reply first byte {reply[0]:#04x} is not a long header")
    sys.exit(1)
# version field must be 0 (Version Negotiation)
ver = struct.unpack(">I", reply[1:5])[0]
if ver != 0:
    print(f"FAIL: reply version {ver:#010x}, expected 0 (Version Negotiation)")
    sys.exit(1)
# DCID = our SCID, SCID = our DCID (swapped, RFC 17.2.1)
off = 5
dcl = reply[off]; off += 1
rep_dcid = reply[off:off + dcl]; off += dcl
scl = reply[off]; off += 1
rep_scid = reply[off:off + scl]; off += scl
if rep_dcid != scid or rep_scid != dcid:
    print(f"FAIL: connection ids not echoed/swapped correctly "
          f"(dcid={rep_dcid.hex()} scid={rep_scid.hex()})")
    sys.exit(1)
# the version list must advertise QUIC v1
versions = []
while off + 4 <= len(reply):
    versions.append(struct.unpack(">I", reply[off:off + 4])[0])
    off += 4
if V1 not in versions:
    print(f"FAIL: v1 not in advertised versions {[hex(v) for v in versions]}")
    sys.exit(1)
print(f"ok (Version Negotiation: versions={[hex(v) for v in versions]}, cids swapped)")
