NASM      = nasm
NASMFLAGS = -f elf64 -g -F dwarf -I include/
LD        = ld

SRCS = $(wildcard src/*.asm)
OBJS = $(SRCS:.asm=.o)
INCS = $(wildcard include/*.inc)
BIN  = bin/linnea

# No dependencies: the binary is nasm + ld over src/, statically linked, with no
# libc and no third-party code. The io_uring rings are driven straight from
# src/linnea_ring.asm (io_uring_setup/io_uring_enter), which is what liburing
# used to provide.

all: $(BIN)

$(BIN): $(OBJS)
	$(LD) -o $@ $(OBJS)

src/%.o: src/%.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

# --- crypto self-test binary (own _start; links only what it needs) ---
SELFTEST_BIN  = bin/linnea-selftest
SELFTEST_OBJS = test/crypto/linnea_selftest.o src/linnea_sha256.o \
                src/linnea_fe25519.o src/linnea_x25519.o \
                src/linnea_p256_mont.o src/linnea_p256_fe.o \
                src/linnea_p256_scalar.o src/linnea_p256_point.o \
                src/linnea_p256_ecdsa.o src/linnea_aesgcm.o src/linnea_tls_kdf.o \
                src/linnea_tls_record.o src/linnea_tls.o src/linnea_pem.o \
                src/linnea_print.o src/linnea_string.o
CRYPTO_VECS   = test/crypto/sha256_vectors.inc

$(CRYPTO_VECS): test/crypto/gen_vectors.py
	python3 $< > $@

test/crypto/linnea_selftest.o: test/crypto/linnea_selftest.asm $(INCS) $(CRYPTO_VECS)
	$(NASM) $(NASMFLAGS) -I test/crypto/ -o $@ $<

$(SELFTEST_BIN): $(SELFTEST_OBJS)
	$(LD) -o $@ $^

selftest: $(SELFTEST_BIN)
	./$(SELFTEST_BIN)

# --- TLS interop echo server (test-only; own _start) ---
TLSTEST_BIN  = bin/linnea-tlstest
TLSTEST_OBJS = test/tls/linnea_tlstest.o src/linnea_tls.o \
               src/linnea_tls_kdf.o src/linnea_tls_record.o src/linnea_aesgcm.o \
               src/linnea_sha256.o src/linnea_fe25519.o \
               src/linnea_x25519.o src/linnea_pem.o \
               src/linnea_p256_mont.o src/linnea_p256_fe.o \
               src/linnea_p256_scalar.o src/linnea_p256_point.o \
               src/linnea_p256_ecdsa.o

test/tls/linnea_tlstest.o: test/tls/linnea_tlstest.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(TLSTEST_BIN): $(TLSTEST_OBJS)
	$(LD) -o $@ $^

tlstest: $(TLSTEST_BIN)

# The P-256 signer objects several QUIC message binaries need (build_cert_verify
# reaches into linnea_p256_ecdsa). Defined before first use so prerequisite
# expansion picks it up.
QUICP256 = src/linnea_p256_ecdsa.o src/linnea_p256_mont.o src/linnea_p256_fe.o \
           src/linnea_p256_scalar.o src/linnea_p256_point.o

# --- QUIC crypto known-answer tests (own _start; RFC 9001 vectors) ---
QUICTEST_BIN  = bin/linnea-quictest
QUICTEST_OBJS = test/quic/linnea_quictest.o src/linnea_quic_crypto.o \
                src/linnea_quic.o src/linnea_aesgcm.o src/linnea_sha256.o \
                src/linnea_tls_kdf.o src/linnea_x25519.o src/linnea_fe25519.o \
                src/linnea_print.o src/linnea_string.o $(QUICP256)

test/quic/linnea_quictest.o: test/quic/linnea_quictest.asm test/quic/quic_vectors.inc test/quic/quic_hs_vectors.inc $(INCS)
	$(NASM) $(NASMFLAGS) -I test/quic/ -o $@ $<

$(QUICTEST_BIN): $(QUICTEST_OBJS)
	$(LD) -o $@ $^

quictest: $(QUICTEST_BIN)
	./$(QUICTEST_BIN)

# --- test-only standalone QUIC UDP receiver (own _start) ---
QUICSRV_BIN  = bin/linnea-quicserver
QUICSRV_OBJS = test/quic/linnea_quicserver.o src/linnea_quic.o \
               src/linnea_quic_crypto.o src/linnea_aesgcm.o src/linnea_sha256.o \
               src/linnea_tls_kdf.o src/linnea_x25519.o src/linnea_fe25519.o \
               src/linnea_print.o src/linnea_string.o $(QUICP256)

test/quic/linnea_quicserver.o: test/quic/linnea_quicserver.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(QUICSRV_BIN): $(QUICSRV_OBJS)
	$(LD) -o $@ $^

quicserver: $(QUICSRV_BIN)

# --- test-only: emit encoded QUIC transport parameters for aioquic to parse ---
QUICTP_BIN  = bin/linnea-quictp
QUICTP_OBJS = test/quic/linnea_quictp.o src/linnea_quic.o src/linnea_quic_crypto.o \
              src/linnea_aesgcm.o src/linnea_sha256.o src/linnea_tls_kdf.o \
              src/linnea_x25519.o src/linnea_fe25519.o $(QUICP256)

test/quic/linnea_quictp.o: test/quic/linnea_quictp.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(QUICTP_BIN): $(QUICTP_OBJS)
	$(LD) -o $@ $^

quictp: $(QUICTP_BIN)

# --- test-only: emit a QUIC ServerHello for aioquic's TLS parser ---
QUICSH_BIN  = bin/linnea-quicsh
QUICSH_OBJS = test/quic/linnea_quicsh.o src/linnea_quic.o src/linnea_quic_crypto.o \
              src/linnea_aesgcm.o src/linnea_sha256.o src/linnea_tls_kdf.o \
              src/linnea_x25519.o src/linnea_fe25519.o $(QUICP256)

test/quic/linnea_quicsh.o: test/quic/linnea_quicsh.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(QUICSH_BIN): $(QUICSH_OBJS)
	$(LD) -o $@ $^

quicsh: $(QUICSH_BIN)

# --- test-only: emit a QUIC EncryptedExtensions for aioquic's TLS parser ---
QUICEE_BIN  = bin/linnea-quicee
QUICEE_OBJS = test/quic/linnea_quicee.o src/linnea_quic.o src/linnea_quic_crypto.o \
              src/linnea_aesgcm.o src/linnea_sha256.o src/linnea_tls_kdf.o \
              src/linnea_x25519.o src/linnea_fe25519.o $(QUICP256)

test/quic/linnea_quicee.o: test/quic/linnea_quicee.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(QUICEE_BIN): $(QUICEE_OBJS)
	$(LD) -o $@ $^

quicee: $(QUICEE_BIN)

# --- test-only: emit a Certificate message (real chain) for aioquic ---
QUICCERT_BIN  = bin/linnea-quiccert
QUICCERT_OBJS = test/quic/linnea_quiccert.o src/linnea_quic.o src/linnea_quic_crypto.o \
                src/linnea_aesgcm.o src/linnea_sha256.o src/linnea_tls_kdf.o \
                src/linnea_x25519.o src/linnea_fe25519.o src/linnea_pem.o $(QUICP256)

test/quic/linnea_quiccert.o: test/quic/linnea_quiccert.asm test/tls/server.crt $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(QUICCERT_BIN): $(QUICCERT_OBJS)
	$(LD) -o $@ $^

quiccert: $(QUICCERT_BIN)

# --- test-only: CertificateVerify (signed) and Finished for aioquic ---
QUICMSG_OBJS = src/linnea_quic.o src/linnea_quic_crypto.o src/linnea_aesgcm.o \
               src/linnea_sha256.o src/linnea_tls_kdf.o src/linnea_x25519.o \
               src/linnea_fe25519.o src/linnea_pem.o $(QUICP256)

test/quic/linnea_quiccv.o: test/quic/linnea_quiccv.asm test/tls/server.key $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<
test/quic/linnea_quicfin.o: test/quic/linnea_quicfin.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

bin/linnea-quiccv: test/quic/linnea_quiccv.o $(QUICMSG_OBJS)
	$(LD) -o $@ $^
bin/linnea-quicfin: test/quic/linnea_quicfin.o $(QUICMSG_OBJS)
	$(LD) -o $@ $^

quiccv: bin/linnea-quiccv
quicfin: bin/linnea-quicfin

# --- test-only: a minimal QUIC handshake responder (server Initial) ---
test/quic/linnea_quichs.o: test/quic/linnea_quichs.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

bin/linnea-quichs: test/quic/linnea_quichs.o $(QUICMSG_OBJS) \
                   src/linnea_http3.o src/linnea_qpack.o src/linnea_hpack.o \
                   src/linnea_static.o src/linnea_string.o src/linnea_time.o \
                   src/linnea_quic_conn.o src/linnea_quic_rtx.o src/linnea_quic_server.o \
                   src/linnea_quic_debug.o src/linnea_log.o src/linnea_error.o src/linnea_print.o \
                   src/linnea_config_parse.o src/linnea_network.o
	$(LD) -o $@ $^

quichs: bin/linnea-quichs

# --- test-only: 1-RTT loss-recovery bookkeeping and ACK-range parsing ---
RTXTEST_BIN  = bin/linnea-rtxtest
RTXTEST_OBJS = test/quic/linnea_rtxtest.o src/linnea_quic_rtx.o src/linnea_quic.o \
               src/linnea_quic_crypto.o src/linnea_aesgcm.o src/linnea_sha256.o \
               src/linnea_tls_kdf.o src/linnea_x25519.o src/linnea_fe25519.o \
               src/linnea_print.o src/linnea_string.o $(QUICP256)

test/quic/linnea_rtxtest.o: test/quic/linnea_rtxtest.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(RTXTEST_BIN): $(RTXTEST_OBJS)
	$(LD) -o $@ $^

rtxtest: $(RTXTEST_BIN)
	./$(RTXTEST_BIN)

# --- 0-RTT anti-replay strike-register unit test ---
REPLAYTEST_BIN  = bin/linnea-replaytest
REPLAYTEST_OBJS = test/quic/linnea_replaytest.o src/linnea_quic_crypto.o \
                  src/linnea_aesgcm.o src/linnea_sha256.o src/linnea_tls_kdf.o \
                  src/linnea_x25519.o src/linnea_fe25519.o src/linnea_print.o \
                  src/linnea_string.o $(QUICP256)

test/quic/linnea_replaytest.o: test/quic/linnea_replaytest.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(REPLAYTEST_BIN): $(REPLAYTEST_OBJS)
	$(LD) -o $@ $^

replaytest: $(REPLAYTEST_BIN)
	./$(REPLAYTEST_BIN)

# --- test-only: QUIC connection pool (allocation, exhaustion, idle sweep) ---
POOLTEST_BIN  = bin/linnea-pooltest
POOLTEST_OBJS = test/quic/linnea_pooltest.o src/linnea_quic_conn.o \
                src/linnea_print.o src/linnea_string.o

test/quic/linnea_pooltest.o: test/quic/linnea_pooltest.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(POOLTEST_BIN): $(POOLTEST_OBJS)
	$(LD) -o $@ $^

pooltest: $(POOLTEST_BIN)
	./$(POOLTEST_BIN)

# --- test-only: QPACK decoder (reads a field section on stdin) ---
QPACKTEST_BIN  = bin/linnea-qpacktest
QPACKTEST_OBJS = test/quic/linnea_qpacktest.o src/linnea_qpack.o src/linnea_hpack.o \
                 src/linnea_static.o src/linnea_string.o src/linnea_time.o

test/quic/linnea_qpacktest.o: test/quic/linnea_qpacktest.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(QPACKTEST_BIN): $(QPACKTEST_OBJS)
	$(LD) -o $@ $^

qpacktest: $(QPACKTEST_BIN)

# --- test-only: HTTP/3 request-stream framing (reads a stream on stdin) ---
H3TEST_BIN  = bin/linnea-h3test
H3TEST_OBJS = test/quic/linnea_h3test.o src/linnea_http3.o src/linnea_qpack.o \
              src/linnea_hpack.o src/linnea_quic.o src/linnea_quic_crypto.o \
              src/linnea_aesgcm.o src/linnea_sha256.o src/linnea_tls_kdf.o \
              src/linnea_x25519.o src/linnea_fe25519.o src/linnea_static.o \
              src/linnea_string.o src/linnea_time.o src/linnea_log.o \
              src/linnea_print.o src/linnea_error.o \
              src/linnea_config_parse.o src/linnea_network.o $(QUICP256)

test/quic/linnea_h3test.o: test/quic/linnea_h3test.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(H3TEST_BIN): $(H3TEST_OBJS)
	$(LD) -o $@ $^

h3test: $(H3TEST_BIN)

# --- test-only: HTTP/3 response builder (writes a response to stdout) ---
H3RESP_BIN  = bin/linnea-h3resp
H3RESP_OBJS = test/quic/linnea_h3resp.o src/linnea_http3.o src/linnea_qpack.o \
              src/linnea_hpack.o src/linnea_quic.o src/linnea_quic_crypto.o \
              src/linnea_aesgcm.o src/linnea_sha256.o src/linnea_tls_kdf.o \
              src/linnea_x25519.o src/linnea_fe25519.o src/linnea_static.o \
              src/linnea_string.o src/linnea_time.o src/linnea_log.o \
              src/linnea_print.o src/linnea_error.o \
              src/linnea_config_parse.o src/linnea_network.o $(QUICP256)

test/quic/linnea_h3resp.o: test/quic/linnea_h3resp.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(H3RESP_BIN): $(H3RESP_OBJS)
	$(LD) -o $@ $^

h3resp: $(H3RESP_BIN)

# --- HTTP compliance prober (own _start; a client, not part of the server) ---
PROBE_BIN  = bin/linnea-probe
PROBE_OBJS = test/probe/linnea_probe.o src/linnea_print.o src/linnea_string.o \
             src/linnea_tls_kdf.o src/linnea_tls_record.o src/linnea_aesgcm.o \
             src/linnea_sha256.o src/linnea_x25519.o src/linnea_fe25519.o

test/probe/linnea_probe.o: test/probe/linnea_probe.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(PROBE_BIN): $(PROBE_OBJS)
	$(LD) -o $@ $^

probe: $(PROBE_BIN)

clean:
	rm -f $(OBJS) $(BIN) $(SELFTEST_BIN) $(TLSTEST_BIN) $(QUICTEST_BIN) \
	      test/probe/*.o $(PROBE_BIN) \
	      test/crypto/*.o test/tls/*.o test/quic/*.o $(CRYPTO_VECS)

test: $(BIN) $(SELFTEST_BIN) $(TLSTEST_BIN) $(QUICTEST_BIN) $(QUICSRV_BIN) \
      $(QUICTP_BIN) $(QUICSH_BIN) $(QUICEE_BIN) $(QUICCERT_BIN) \
      bin/linnea-quiccv bin/linnea-quicfin bin/linnea-quichs $(QPACKTEST_BIN) \
      $(H3TEST_BIN) $(H3RESP_BIN) $(POOLTEST_BIN) $(RTXTEST_BIN) $(REPLAYTEST_BIN)
	./test/run_tests.sh

# Install the binary to /usr/local/bin: bin_t under SELinux, so systemd
# may exec it, and the fresh inode picks up the standard label — no
# setcap or restorecon after rebuilds. Run as root (`sudo make install`);
# deliberately not dependent on the build, so root never compiles into
# the tree. Routine deploy:
#   make && sudo make install && sudo systemctl restart linnea
# The systemd unit is a one-time install; see config/linnea.service.
install:
	install -m 0755 $(BIN) /usr/local/bin/linnea

.PHONY: all clean test selftest tlstest install
