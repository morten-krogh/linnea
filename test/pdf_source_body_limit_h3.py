#!/usr/bin/env python3
"""Acceptance probe for the proposed exact PDF source ingress cap over H3.

Usage: pdf_source_body_limit_h3.py PORT [HOST [ORDINARY_CAP [SOURCE_CAP]]]

Run against a TLS Linnea server with the exact source body_limits rule and an
absent proxy backend (accepted bodies return 502). For packet-shape checks,
use small caps such as 256 and 512: the probe asserts that the coalesced
HEADERS+DATA request leaves in exactly one QUIC datagram. A deployment-sized
cap necessarily spans packets; the split-send cases still exercise that path.
"""

import socket
import ssl
import sys
import time
import os

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection, QuicConnectionState
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived, StreamReset


port = int(sys.argv[1])
host = sys.argv[2] if len(sys.argv) > 2 else "vefruna.test"
ordinary = int(sys.argv[3]) if len(sys.argv) > 3 else 256
source_cap = int(sys.argv[4]) if len(sys.argv) > 4 else 512
if not 0 < ordinary < source_cap:
    raise SystemExit("expected 0 < ORDINARY_CAP < SOURCE_CAP")
project = "project_" + "0" * 25 + "1"
source = f"/projects/{project}/source"
addr = ("127.0.0.1", port)


def vi(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    if n < 1 << 30:
        return (0x80000000 | n).to_bytes(4, "big")
    return (0xC000000000000000 | n).to_bytes(8, "big")


def read_vi(data, offset):
    if offset >= len(data):
        return None
    size = 1 << (data[offset] >> 6)
    if offset + size > len(data):
        return None
    return int.from_bytes(data[offset:offset + size], "big") & ((1 << (size * 8 - 2)) - 1), offset + size


config = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
config.verify_mode = ssl.CERT_NONE
config.server_name = host
conn = QuicConnection(configuration=config)
clock = [0.0]
conn.connect(addr, now=clock[0])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(0.25)


def pump():
    datagrams = conn.datagrams_to_send(now=clock[0])
    for data, _ in datagrams:
        sock.sendto(data, addr)
    return len(datagrams)


def receive():
    try:
        data, _ = sock.recvfrom(65535)
    except socket.timeout:
        clock[0] += 0.25
        if conn._close_at is not None:
            conn.handle_timer(now=clock[0])
        return []
    clock[0] += 0.01
    conn.receive_datagram(data, addr, now=clock[0])
    events = []
    event = conn.next_event()
    while event is not None:
        events.append(event)
        event = conn.next_event()
    return events


def status(response, stream_id):
    head = read_vi(response, 0)
    if head is None:
        return None
    frame_type, i = head
    length = read_vi(response, i)
    if length is None:
        return None
    size, i = length
    if frame_type != 1 or i + size > len(response):
        return None
    _, fields = pylsqpack.Decoder(0, 0).feed_header(stream_id, response[i:i + size])
    return dict(fields).get(b":status", b"?").decode()


def spill_sizes(worker_pid, marker):
    """Sizes of this fixture's anonymous capture files in a Linnea worker."""
    fd_dir = f"/proc/{worker_pid}/fd"
    sizes = []
    for name in os.listdir(fd_dir):
        path = os.path.join(fd_dir, name)
        try:
            target = os.readlink(path)
            if marker in target and target.endswith(" (deleted)"):
                sizes.append(os.stat(path).st_size)
        except (FileNotFoundError, PermissionError, OSError):
            pass  # The worker can close a descriptor between readlink and stat.
    return sizes


def adjacent_spill_probe(worker_pid, marker):
    """Leave an adjacent-route upload open long enough to inspect capture."""
    stream_id = conn.get_next_available_stream_id()
    encoder = pylsqpack.Encoder()
    encoder.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = encoder.encode(stream_id, [
        (b":method", b"POST"), (b":path", source.replace("/source", "/notes").encode()),
        (b":scheme", b"https"), (b":authority", host.encode()),
    ])
    head = vi(1) + vi(len(fields)) + fields
    body = vi(0) + vi(ordinary + 1) + b"A" * (ordinary + 1)
    conn.send_stream_data(stream_id, head + body, end_stream=False)
    pump()
    largest = 0
    response = b""
    deadline = time.monotonic() + 0.5
    while time.monotonic() < deadline:
        largest = max([largest, *spill_sizes(worker_pid, marker)])
        for event in receive():
            if isinstance(event, StreamDataReceived) and event.stream_id == stream_id:
                response += event.data
        pump()
    conn.send_stream_data(stream_id, b"", end_stream=True)
    pump()
    deadline = time.monotonic() + 10
    while status(response, stream_id) is None and time.monotonic() < deadline:
        largest = max([largest, *spill_sizes(worker_pid, marker)])
        for event in receive():
            if isinstance(event, StreamDataReceived) and event.stream_id == stream_id:
                response += event.data
        pump()
    return status(response, stream_id), largest


def request(path, length, *, method="POST", split=False, authority=host,
            content_length=True, require_one_datagram=False,
            fragment_headers=0, fields_override=None):
    stream_id = conn.get_next_available_stream_id()
    encoder = pylsqpack.Encoder()
    encoder.apply_settings(max_table_capacity=0, blocked_streams=0)
    headers = [(b":method", method.encode()), (b":path", path.encode()),
               (b":scheme", b"https"), (b":authority", authority.encode())]
    if content_length:
        headers.append((b"content-length", str(length).encode()))
    _, fields = encoder.encode(stream_id, headers)
    if fields_override is not None:
        fields = fields_override
    head = vi(1) + vi(len(fields)) + fields
    body = vi(0) + vi(length) + b"A" * length
    if fragment_headers:
        if not 0 < fragment_headers < len(head):
            return "invalid HEADERS split"
        conn.send_stream_data(stream_id, head[:fragment_headers], end_stream=False)
        if pump() == 0:
            return "HEADERS fragment not flushed"
        clock[0] += 0.01
        conn.send_stream_data(stream_id, head[fragment_headers:], end_stream=False)
        if pump() == 0:
            return "HEADERS remainder not flushed"
        clock[0] += 0.01
        conn.send_stream_data(stream_id, body, end_stream=True)
    elif split:
        conn.send_stream_data(stream_id, head, end_stream=False)
        if pump() == 0:
            return "HEADERS not flushed"
        clock[0] += 0.01
        conn.send_stream_data(stream_id, body, end_stream=True)
    else:
        conn.send_stream_data(stream_id, head + body, end_stream=True)
    count = pump()
    if require_one_datagram and count != 1:
        return f"coalesced request used {count} datagrams"
    response = b""
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        for event in receive():
            if isinstance(event, StreamDataReceived) and event.stream_id == stream_id:
                response += event.data
                found = status(response, stream_id)
                if found is not None:
                    return found
            if isinstance(event, StreamReset) and event.stream_id == stream_id:
                return "reset"
            if isinstance(event, ConnectionTerminated):
                return "connection closed"
        if conn._state in (QuicConnectionState.CLOSING,
                           QuicConnectionState.DRAINING,
                           QuicConnectionState.TERMINATED):
            return "connection closed"
        pump()
    return "no H3 response"


try:
    pump()
    deadline = time.monotonic() + 10
    while not conn._handshake_confirmed and time.monotonic() < deadline:
        receive()
        pump()
    if not conn._handshake_confirmed:
        raise RuntimeError("H3 handshake did not complete")
    while conn.next_event() is not None:
        pass

    above_ordinary = ordinary + 1
    cases = [
        ("source HEADERS+DATA one packet", source, above_ordinary, "POST", False, True, "502"),
        ("source HEADERS then DATA", source, above_ordinary, "POST", True, False, "502"),
        ("source no Content-Length", source, above_ordinary, "POST", True, False, "502"),
        ("source exactly at scoped cap", source, source_cap, "POST", True, False, "502"),
        ("source scoped cap+1", source, source_cap + 1, "POST", True, False, "413"),
        ("adjacent route", source.replace("/source", "/notes"), above_ordinary, "POST", True, False, "413"),
        ("wrong method", source, above_ordinary, "PUT", True, False, "413"),
        ("query", source + "?other=1", above_ordinary, "POST", True, False, "413"),
        ("encoded path", source.replace("/source", "/%73ource"), above_ordinary, "POST", True, False, "413"),
        ("extra path", source + "/extra", above_ordinary, "POST", True, False, "413"),
        ("malformed project ID", source.replace(project, "project_" + "8" * 26),
         above_ordinary, "POST", True, False, "413"),
    ]
    failed = []
    for label, path, length, method, split, single, expected in cases:
        got = request(path, length, method=method, split=split,
                      content_length=label != "source no Content-Length",
                      require_one_datagram=single and source_cap < 1000)
        if got != expected:
            failed.append(f"{label}: got {got}, expected {expected}")
    for label, path, expected in [
        ("source fragmented frame header", source, "502"),
        ("adjacent fragmented frame header", source.replace("/source", "/notes"), "413"),
    ]:
        got = request(path, above_ordinary, fragment_headers=1)
        if got != expected:
            failed.append(f"{label}: got {got}, expected {expected}")
    # Splitting inside the QPACK field block takes a different reassembly path
    # from splitting the frame's varint header.
    for path, expected in [(source, "502"),
                           (source.replace("/source", "/notes"), "413")]:
        got = request(path, above_ordinary, fragment_headers=12,
                      content_length=False)
        if got != expected:
            failed.append(f"QPACK field-block fragment {path}: got {got}, expected {expected}")
    coalesced = os.environ.get("LINNEA_H3_COALESCED_AUTHORITY")
    if coalesced:
        # The fixture must put the source rule on `host` only and configure
        # `coalesced` as a second vhost covered by the same certificate.
        for authority, expected in [(host, "502"), (coalesced, "413"),
                                    (host, "502")]:
            got = request(source, above_ordinary, authority=authority, split=True)
            if got != expected:
                failed.append(f"coalesced {authority}: got {got}, expected {expected}")
    worker_pid = os.environ.get("LINNEA_H3_WORKER_PID")
    if worker_pid:
        marker = os.environ.get("LINNEA_H3_SPILL_MARKER")
        if not marker:
            failed.append("LINNEA_H3_SPILL_MARKER required with worker PID")
        else:
            got, largest = adjacent_spill_probe(worker_pid, marker)
            if got != "413" or largest > ordinary:
                failed.append(f"adjacent capture: status {got}, peak {largest}, ordinary cap {ordinary}")
    other = request(source, above_ordinary, authority="other.test", split=True)
    if other != "413":
        failed.append(f"other authority: got {other}, expected 413")
    # Required Insert Count 1 is invalid with Linnea's advertised dynamic
    # table capacity 0. RFC 9204 makes decompression failure a connection
    # error, so this must run last on the connection.
    invalid = request(source, above_ordinary, fields_override=b"\x01\x00")
    if invalid != "connection closed":
        failed.append(f"invalid QPACK dynamic reference: got {invalid}, expected connection close")
    if failed:
        print("\n".join(failed))
        raise SystemExit(1)
    print("H3 exact PDF source cap: OK")
finally:
    sock.close()
