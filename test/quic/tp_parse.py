#!/usr/bin/env python3
# Parse linnea's encoded QUIC transport parameters (read from stdin) with
# aioquic and confirm the values, proving the encoding interoperates.
import sys

from aioquic.buffer import Buffer
from aioquic.quic.packet import pull_quic_transport_parameters

data = sys.stdin.buffer.read()
tp = pull_quic_transport_parameters(Buffer(data=data))

assert tp.original_destination_connection_id == bytes(
    [0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7]), \
    tp.original_destination_connection_id
assert tp.initial_source_connection_id == bytes(
    [0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7]), \
    tp.initial_source_connection_id
assert tp.max_idle_timeout == 30000, tp.max_idle_timeout
assert tp.initial_max_data == 1048576, tp.initial_max_data
assert tp.initial_max_stream_data_bidi_local == 262144
assert tp.initial_max_streams_bidi == 100, tp.initial_max_streams_bidi
assert tp.initial_max_streams_uni == 100
print("ok")
