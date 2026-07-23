#!/usr/bin/env python3
# Generate a deterministic PNG test asset (no third-party deps) for the served
# document roots. A real binary image over ~100 KB exercises the static MIME
# path (image/png) and, over HTTP/3, the chunked large-response path (Q49): the
# body is delivered as many STREAM-frame chunks, each under the datagram floor.
# Usage: mk_test_image.py <out.png> [width] [height]
import zlib
import struct
import math
import sys

out = sys.argv[1]
W = int(sys.argv[2]) if len(sys.argv) > 2 else 640
H = int(sys.argv[3]) if len(sys.argv) > 3 else 420
g_dark = (0x2a, 0x60, 0x41)          # linnea green
g_lite = (0xf3, 0xf7, 0xf0)
cx, cy = W * 0.32, H * 0.30
seed = 1234567


def rnd():
    global seed
    seed = (seed * 1103515245 + 12345) & 0x7fffffff
    return (seed >> 16) & 0x01        # 0..1 dither: keeps it moderately sized


raw = bytearray()
for y in range(H):
    line = bytearray()
    for x in range(W):
        t = x / W * 0.6 + y / H * 0.4
        d = math.hypot(x - cx, y - cy) / (W * 0.7)
        hi = max(0.0, 0.35 - d)
        for k in range(3):
            v = g_dark[k] + (g_lite[k] - g_dark[k]) * t + hi * 120 + rnd()
            line.append(max(0, min(255, int(v))))
    raw.append(1)                     # PNG Sub filter for this scanline
    for i in range(len(line)):
        left = line[i - 3] if i >= 3 else 0
        raw.append((line[i] - left) & 0xff)


def chunk(typ, data):
    c = typ + data
    return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)


png = b"\x89PNG\r\n\x1a\n"
png += chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 2, 0, 0, 0))
png += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
png += chunk(b"IEND", b"")
with open(out, "wb") as f:
    f.write(png)
print(f"{W}x{H} PNG -> {out} ({len(png)} bytes)")
