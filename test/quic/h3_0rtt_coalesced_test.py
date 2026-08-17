#!/usr/bin/env python3
"""Exercise more than one coalesced 0-RTT packet (RFC 9000 12.2).

The server receives a ClientHello and two separately-built 0-RTT packets in
one UDP datagram.  The first case carries two complete requests; the second
splits one request across the two early packets.  Both cases must be
reassembled and both early packet numbers must be acknowledged.
"""
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived
from aioquic.quic.logger import QuicLogger

port = int(sys.argv[1])
ADDR = ("127.0.0.1", port)


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def rvlq(buf, pos):
    n = 1 << (buf[pos] >> 6)
    end = pos + n
    if end > len(buf):
        raise AssertionError("truncated QUIC varint")
    value = buf[pos] & 0x3F
    for i in range(pos + 1, end):
        value = (value << 8) | buf[i]
    return value, end


def long_packets(datagram):
    """Return (type bits, packet bytes) for long-header packets in datagram."""
    packets = []
    pos = 0
    while pos < len(datagram) and datagram[pos] & 0x80:
        start = pos
        type_bits = datagram[pos] & 0x30
        if pos + 6 > len(datagram):
            raise AssertionError("truncated QUIC long header")
        dcid_len = datagram[pos + 5]
        pos += 6 + dcid_len
        if pos >= len(datagram):
            raise AssertionError("truncated QUIC source connection id")
        scid_len = datagram[pos]
        pos += 1 + scid_len
        if type_bits == 0x00:          # QUIC v1 Initial; no Retry is used here.
            token_len, pos = rvlq(datagram, pos)
            pos += token_len
        length, length_end = rvlq(datagram, pos)
        end = length_end + length
        if end > len(datagram):
            raise AssertionError("QUIC packet length runs past datagram")
        packets.append((type_bits, datagram[start:end]))
        pos = end
    return packets


def h3_get(path):
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(0, [(b":method", b"GET"),
                               (b":path", path.encode()),
                               (b":scheme", b"https"),
                               (b":authority", b"h3.test")])
    return vlq(1) + vlq(len(fields)) + fields


def full_handshake():
    tickets = []
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg, session_ticket_handler=tickets.append)
    conn.connect(ADDR, now=0.0)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)

    def flush(now):
        for datagram, _ in conn.datagrams_to_send(now=now):
            sock.sendto(datagram, ADDR)

    flush(0.0)
    packet, _ = sock.recvfrom(4096)
    conn.receive_datagram(packet, ADDR, now=0.1)
    flush(0.2)
    packet, _ = sock.recvfrom(4096)
    conn.receive_datagram(packet, ADDR, now=0.3)
    while conn.next_event() is not None:
        pass
    sock.close()
    assert tickets, "no ticket from the first handshake"
    return tickets[0]


def run_early(ticket, parts, expected_streams):
    logger = QuicLogger()
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    cfg.session_ticket = ticket
    cfg.quic_logger = logger
    conn = QuicConnection(configuration=cfg)
    conn.connect(ADDR, now=0.0)

    # Build each early packet separately, then coalesce the resulting protected
    # packets with the Initial. This preserves valid packet numbers and AEAD
    # tags while creating the wire shape the server used to stop after packet 1.
    outgoing = []
    for stream_id, data, end_stream in parts:
        conn.send_stream_data(stream_id, data, end_stream=end_stream)
        outgoing.extend(conn.datagrams_to_send(now=0.0))

    initial = None
    early = []
    for datagram, _ in outgoing:
        for type_bits, packet in long_packets(datagram):
            if type_bits == 0x00:
                initial = packet
            elif type_bits == 0x10:
                early.append(packet)
    assert initial is not None, "no Initial packet in early flight"
    assert len(early) >= 2, f"expected two 0-RTT packets, got {len(early)}"
    coalesced = initial + b"".join(early)
    if len(coalesced) < 1200:
        coalesced += b"\x00" * (1200 - len(coalesced))
    # linnea_quic_rxbuf is deliberately 2048 bytes; keep this regression below
    # that receive bound while still forcing separate protected packets.
    assert len(coalesced) <= 2048, f"coalesced datagram too large: {len(coalesced)}"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.15)
    sock.sendto(coalesced, ADDR)
    response_streams = {}
    now = 0.1
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline and len(response_streams) < len(expected_streams):
        try:
            packet, _ = sock.recvfrom(4096)
            conn.receive_datagram(packet, ADDR, now=now)
            event = conn.next_event()
            while event is not None:
                if isinstance(event, StreamDataReceived) and event.stream_id in expected_streams:
                    response_streams.setdefault(event.stream_id, bytearray()).extend(event.data)
                event = conn.next_event()
        except socket.timeout:
            pass
        try:
            conn.handle_timer(now=now)
        except Exception:
            pass
        for packet, _ in conn.datagrams_to_send(now=now):
            sock.sendto(packet, ADDR)
        now += 0.1
    sock.close()

    assert conn._handshake_confirmed, "handshake not confirmed"
    assert conn.tls.early_data_accepted, "server did not accept 0-RTT early data"
    assert set(response_streams) == set(expected_streams), \
        f"missing early responses: got {sorted(response_streams)}"
    for stream_id, response in response_streams.items():
        assert response, f"empty response on stream {stream_id}"

    sent_early_pns = []
    acked = set()

    def ev_name(event):
        return event.get("name") if isinstance(event, dict) else event[1]

    def ev_data(event):
        return (event.get("data") if isinstance(event, dict) else event[3]) or {}

    events = []
    for trace in logger.to_dict().get("traces", []):
        events.extend(trace.get("events", []))
    for event in events:
        name = ev_name(event)
        data = ev_data(event)
        if name == "transport:packet_sent":
            header = data.get("header", {})
            if header.get("packet_type", "") in ("0RTT", "zerortt", "0rtt"):
                sent_early_pns.append(int(header.get("packet_number", -1)))
        elif name == "transport:packet_received":
            for frame in data.get("frames", []):
                if frame.get("frame_type") != "ack":
                    continue
                for value in frame.get("acked_ranges", []):
                    lo, hi = value if isinstance(value, (list, tuple)) else (value, value)
                    acked.update(range(int(lo), int(hi) + 1))
    assert len(sent_early_pns) >= 2, f"client did not emit two 0-RTT packets: {sent_early_pns}"
    assert set(sent_early_pns).issubset(acked), \
        f"server ACKs {sorted(acked)} omit early packets {sent_early_pns}"


ticket = full_handshake()

# Two complete requests, each generated in its own 0-RTT packet.
run_early(ticket,
          [(0, h3_get("/hello.txt"), True),
           (4, h3_get("/hello.txt"), True)],
          {0, 4})

# One request split between two 0-RTT packets. The normal stream reassembly
# path must join the offset-0 prefix and the FIN-bearing suffix.
request = h3_get("/hello.txt")
split = 4
run_early(ticket,
          [(0, request[:split], False),
           (0, request[split:], True)],
          {0})

print("ok (two coalesced 0-RTT packets: two requests and one split request)")
