#!/usr/bin/env python3
# Parse linnea's QUIC EncryptedExtensions (stdin) with aioquic: the ALPN must
# be h3, and the transport-parameters extension (0x39) must decode.
import sys

from aioquic.buffer import Buffer
from aioquic import tls
from aioquic.quic.packet import pull_quic_transport_parameters

ee = tls.pull_encrypted_extensions(Buffer(data=sys.stdin.buffer.read()))
assert ee.alpn_protocol == "h3", ee.alpn_protocol

# the QUIC transport parameters ride as extension 57 (0x39)
tp_ext = dict(ee.other_extensions).get(57)
assert tp_ext is not None, "no transport_parameters extension"
tp = pull_quic_transport_parameters(Buffer(data=tp_ext))
assert tp.original_destination_connection_id == bytes(
    [0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7])
assert tp.initial_max_data == 1048576, tp.initial_max_data
print("ok")
