NASM      = nasm
NASMFLAGS = -f elf64 -g -F dwarf -I include/
LD        = ld

# src/ is split into a shared library plus one directory per executable:
#   src/lib/    — code both executables link (crypto, tls/quic primitives, util)
#   src/server/ — the server application (its own _start)
#   src/probe/  — the linnea-probe client (its own _start)
LIBSRCS = $(wildcard src/lib/*.asm)
LIBOBJS = $(LIBSRCS:.asm=.o)
SRVSRCS = $(wildcard src/server/*.asm)
SRVOBJS = $(SRVSRCS:.asm=.o)
INCS = $(wildcard include/*.inc)
BIN  = bin/linnea

# Shared P-256 signer objects (build_cert_verify reaches into linnea_p256_ecdsa);
# used by linnea-probe and several QUIC message binaries. Defined up here so the
# product variables below can reference it before its former mid-file location.
QUICP256 = src/lib/linnea_p256_ecdsa.o src/lib/linnea_p256_mont.o src/lib/linnea_p256_fe.o \
           src/lib/linnea_p256_scalar.o src/lib/linnea_p256_point.o

# linnea-probe: a standalone HTTP/1.1+HTTP/2+HTTP/3 compliance prober. A shipped
# product in its own right (installed alongside the server), NOT test code — it
# has its own _start and links only the subset of server objects it reuses.
PROBE_BIN  = bin/linnea-probe
PROBE_OBJS = src/probe/linnea_probe.o src/lib/linnea_print.o src/lib/linnea_string.o \
             src/lib/linnea_tls_kdf.o src/lib/linnea_tls_record.o src/lib/linnea_aesgcm.o \
             src/lib/linnea_sha256.o src/lib/linnea_x25519.o src/lib/linnea_fe25519.o \
             src/lib/linnea_quic.o src/lib/linnea_quic_crypto.o $(QUICP256)

# No dependencies: the binary is nasm + ld over src/, statically linked, with no
# libc and no third-party code. The io_uring rings are driven straight from
# src/server/linnea_ring.asm (io_uring_setup/io_uring_enter), which is what liburing
# used to provide.

# The two backends linnea proxies to, named here rather than beside their rules
# further down for the same reason QUICP256 is: a prerequisite list is expanded
# where it is WRITTEN, so a variable defined after `all` expands to nothing
# there and silently drops the target. Their objects and link rules stay below.
API_BIN = bin/linnea-api
WS_BIN  = bin/linnea-ws

# Everything `install` copies, so that `make` alone leaves nothing behind it.
# The two backends used to be built only as a side effect of `install`, which
# meant a plain `make` after editing one of them silently kept the old binary
# and `sudo make install` then compiled it as root. They are small; building
# them always costs two links.
all: $(BIN) $(PROBE_BIN) $(API_BIN) $(WS_BIN)

$(BIN): $(LIBOBJS) $(SRVOBJS)
	$(LD) -o $@ $^

# One pattern rule assembles every .asm under src/ (% spans the subdirectory).
src/%.o: src/%.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

# --- crypto self-test binary (own _start; links only what it needs) ---
SELFTEST_BIN  = bin/linnea-selftest
SELFTEST_OBJS = test/crypto/linnea_selftest.o src/lib/linnea_sha256.o \
                src/lib/linnea_sha1.o src/lib/linnea_base64.o \
                src/lib/linnea_fe25519.o src/lib/linnea_x25519.o \
                src/lib/linnea_p256_mont.o src/lib/linnea_p256_fe.o \
                src/lib/linnea_p256_scalar.o src/lib/linnea_p256_point.o \
                src/lib/linnea_p256_ecdsa.o src/lib/linnea_aesgcm.o src/lib/linnea_tls_kdf.o \
                src/lib/linnea_tls_record.o src/server/linnea_tls.o src/server/linnea_pem.o \
                src/lib/linnea_print.o src/lib/linnea_string.o
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
TLSTEST_OBJS = test/tls/linnea_tlstest.o src/server/linnea_tls.o \
               src/lib/linnea_tls_kdf.o src/lib/linnea_tls_record.o src/lib/linnea_aesgcm.o \
               src/lib/linnea_sha256.o src/lib/linnea_fe25519.o \
               src/lib/linnea_x25519.o src/server/linnea_pem.o \
               src/lib/linnea_p256_mont.o src/lib/linnea_p256_fe.o \
               src/lib/linnea_p256_scalar.o src/lib/linnea_p256_point.o \
               src/lib/linnea_p256_ecdsa.o

test/tls/linnea_tlstest.o: test/tls/linnea_tlstest.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(TLSTEST_BIN): $(TLSTEST_OBJS)
	$(LD) -o $@ $^

tlstest: $(TLSTEST_BIN)

# --- QUIC crypto known-answer tests (own _start; RFC 9001 vectors) ---
QUICTEST_BIN  = bin/linnea-quictest
QUICTEST_OBJS = test/quic/linnea_quictest.o src/lib/linnea_quic_crypto.o \
                src/lib/linnea_quic.o src/lib/linnea_aesgcm.o src/lib/linnea_sha256.o \
                src/lib/linnea_tls_kdf.o src/lib/linnea_x25519.o src/lib/linnea_fe25519.o \
                src/lib/linnea_print.o src/lib/linnea_string.o $(QUICP256)

test/quic/linnea_quictest.o: test/quic/linnea_quictest.asm test/quic/quic_vectors.inc test/quic/quic_hs_vectors.inc $(INCS)
	$(NASM) $(NASMFLAGS) -I test/quic/ -o $@ $<

$(QUICTEST_BIN): $(QUICTEST_OBJS)
	$(LD) -o $@ $^

quictest: $(QUICTEST_BIN)
	./$(QUICTEST_BIN)

# --- test-only standalone QUIC UDP receiver (own _start) ---
QUICSRV_BIN  = bin/linnea-quicserver
QUICSRV_OBJS = test/quic/linnea_quicserver.o src/lib/linnea_quic.o \
               src/lib/linnea_quic_crypto.o src/lib/linnea_aesgcm.o src/lib/linnea_sha256.o \
               src/lib/linnea_tls_kdf.o src/lib/linnea_x25519.o src/lib/linnea_fe25519.o \
               src/lib/linnea_print.o src/lib/linnea_string.o $(QUICP256)

test/quic/linnea_quicserver.o: test/quic/linnea_quicserver.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(QUICSRV_BIN): $(QUICSRV_OBJS)
	$(LD) -o $@ $^

quicserver: $(QUICSRV_BIN)

# --- test-only: emit encoded QUIC transport parameters for aioquic to parse ---
QUICTP_BIN  = bin/linnea-quictp
QUICTP_OBJS = test/quic/linnea_quictp.o src/lib/linnea_quic.o src/lib/linnea_quic_crypto.o \
              src/lib/linnea_aesgcm.o src/lib/linnea_sha256.o src/lib/linnea_tls_kdf.o \
              src/lib/linnea_x25519.o src/lib/linnea_fe25519.o $(QUICP256)

test/quic/linnea_quictp.o: test/quic/linnea_quictp.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(QUICTP_BIN): $(QUICTP_OBJS)
	$(LD) -o $@ $^

quictp: $(QUICTP_BIN)

# --- test-only: emit a QUIC ServerHello for aioquic's TLS parser ---
QUICSH_BIN  = bin/linnea-quicsh
QUICSH_OBJS = test/quic/linnea_quicsh.o src/lib/linnea_quic.o src/lib/linnea_quic_crypto.o \
              src/lib/linnea_aesgcm.o src/lib/linnea_sha256.o src/lib/linnea_tls_kdf.o \
              src/lib/linnea_x25519.o src/lib/linnea_fe25519.o $(QUICP256)

test/quic/linnea_quicsh.o: test/quic/linnea_quicsh.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(QUICSH_BIN): $(QUICSH_OBJS)
	$(LD) -o $@ $^

quicsh: $(QUICSH_BIN)

# --- test-only: emit a QUIC EncryptedExtensions for aioquic's TLS parser ---
QUICEE_BIN  = bin/linnea-quicee
QUICEE_OBJS = test/quic/linnea_quicee.o src/lib/linnea_quic.o src/lib/linnea_quic_crypto.o \
              src/lib/linnea_aesgcm.o src/lib/linnea_sha256.o src/lib/linnea_tls_kdf.o \
              src/lib/linnea_x25519.o src/lib/linnea_fe25519.o $(QUICP256)

test/quic/linnea_quicee.o: test/quic/linnea_quicee.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(QUICEE_BIN): $(QUICEE_OBJS)
	$(LD) -o $@ $^

quicee: $(QUICEE_BIN)

# --- test-only: emit a Certificate message (real chain) for aioquic ---
QUICCERT_BIN  = bin/linnea-quiccert
QUICCERT_OBJS = test/quic/linnea_quiccert.o src/lib/linnea_quic.o src/lib/linnea_quic_crypto.o \
                src/lib/linnea_aesgcm.o src/lib/linnea_sha256.o src/lib/linnea_tls_kdf.o \
                src/lib/linnea_x25519.o src/lib/linnea_fe25519.o src/server/linnea_pem.o $(QUICP256)

test/quic/linnea_quiccert.o: test/quic/linnea_quiccert.asm test/tls/server.crt $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(QUICCERT_BIN): $(QUICCERT_OBJS)
	$(LD) -o $@ $^

quiccert: $(QUICCERT_BIN)

# --- test-only: CertificateVerify (signed) and Finished for aioquic ---
QUICMSG_OBJS = src/lib/linnea_quic.o src/lib/linnea_quic_crypto.o src/lib/linnea_aesgcm.o \
               src/lib/linnea_sha256.o src/lib/linnea_tls_kdf.o src/lib/linnea_x25519.o \
               src/lib/linnea_fe25519.o src/server/linnea_pem.o $(QUICP256)

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
                   src/server/linnea_http3.o src/server/linnea_qpack.o src/server/linnea_hpack.o \
                   src/server/linnea_static.o src/lib/linnea_string.o src/server/linnea_time.o \
                   src/server/linnea_quic_conn.o src/server/linnea_quic_rtx.o src/server/linnea_quic_server.o \
                   src/server/linnea_quic_debug.o src/server/linnea_log.o src/server/linnea_error.o src/lib/linnea_print.o \
                   src/server/linnea_config.o src/server/linnea_config_parse.o src/server/linnea_network.o \
                   src/server/linnea_ratelimit.o
	$(LD) -o $@ $^

quichs: bin/linnea-quichs

# --- test-only: 1-RTT loss-recovery bookkeeping and ACK-range parsing ---
RTXTEST_BIN  = bin/linnea-rtxtest
RTXTEST_OBJS = test/quic/linnea_rtxtest.o src/server/linnea_quic_rtx.o src/lib/linnea_quic.o \
               src/lib/linnea_quic_crypto.o src/lib/linnea_aesgcm.o src/lib/linnea_sha256.o \
               src/lib/linnea_tls_kdf.o src/lib/linnea_x25519.o src/lib/linnea_fe25519.o \
               src/lib/linnea_print.o src/lib/linnea_string.o $(QUICP256)

test/quic/linnea_rtxtest.o: test/quic/linnea_rtxtest.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(RTXTEST_BIN): $(RTXTEST_OBJS)
	$(LD) -o $@ $^

rtxtest: $(RTXTEST_BIN)
	./$(RTXTEST_BIN)

# --- 0-RTT anti-replay strike-register unit test ---
# The little HTTP/1.1 backend behind the site's /api location: it takes the
# uploads the index page sends and answers with their size and checksum.
# API_BIN is defined up beside `all`, which needs it before this point.
API_OBJS        = test/api/linnea_api.o src/lib/linnea_sha256.o src/lib/linnea_print.o \
                  src/lib/linnea_string.o

test/api/linnea_api.o: test/api/linnea_api.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(API_BIN): $(API_OBJS)
	$(LD) -o $@ $^

api: $(API_BIN)

# The WebSocket backend behind linnea2.amberbio.com's /ws location. linnea
# relays an accepted upgrade as an opaque tunnel, so all of RFC 6455 lives
# here — including the SHA-1 and base64 the accept token is made of.
# WS_BIN, likewise, is defined up beside `all`.
WS_OBJS         = test/api/linnea_ws.o src/lib/linnea_sha1.o \
                  src/lib/linnea_base64.o src/lib/linnea_print.o src/lib/linnea_string.o

test/api/linnea_ws.o: test/api/linnea_ws.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(WS_BIN): $(WS_OBJS)
	$(LD) -o $@ $^

ws: $(WS_BIN)

# The same source at a 3 s ping and a 1.5 s grace, for the fast suite. The
# heartbeat check is the most expensive in the file at 105 s, and all of it is
# waiting out the SHIPPED intervals; against this it proves the same mechanism
# -- a client that answers lives, one that goes silent is dropped -- in ~13 s.
# What it stops proving is the interval itself, which is why the full suite
# keeps running against $(WS_BIN). Its own object file: -D changes the output
# but not the source's timestamp, so sharing linnea_ws.o would hand whichever
# build ran last to both.
WS_FAST_BIN     = bin/linnea-ws-fast
WS_FAST_OBJS    = test/api/linnea_ws_fast.o src/lib/linnea_sha1.o \
                  src/lib/linnea_base64.o src/lib/linnea_print.o src/lib/linnea_string.o

test/api/linnea_ws_fast.o: test/api/linnea_ws.asm $(INCS)
	$(NASM) $(NASMFLAGS) -DPING_EVERY_MS=3000 -DPONG_WITHIN_MS=1500 -o $@ $<

$(WS_FAST_BIN): $(WS_FAST_OBJS)
	$(LD) -o $@ $^

wsfast: $(WS_FAST_BIN)

REPLAYTEST_BIN  = bin/linnea-replaytest
REPLAYTEST_OBJS = test/quic/linnea_replaytest.o src/lib/linnea_quic_crypto.o \
                  src/lib/linnea_quic.o \
                  src/lib/linnea_aesgcm.o src/lib/linnea_sha256.o src/lib/linnea_tls_kdf.o \
                  src/lib/linnea_x25519.o src/lib/linnea_fe25519.o src/lib/linnea_print.o \
                  src/lib/linnea_string.o $(QUICP256)

test/quic/linnea_replaytest.o: test/quic/linnea_replaytest.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(REPLAYTEST_BIN): $(REPLAYTEST_OBJS)
	$(LD) -o $@ $^

replaytest: $(REPLAYTEST_BIN)
	./$(REPLAYTEST_BIN)

# --- test-only: QUIC connection pool (allocation, exhaustion, idle sweep) ---
POOLTEST_BIN  = bin/linnea-pooltest
POOLTEST_OBJS = test/quic/linnea_pooltest.o src/server/linnea_quic_conn.o \
                src/lib/linnea_print.o src/lib/linnea_string.o

test/quic/linnea_pooltest.o: test/quic/linnea_pooltest.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(POOLTEST_BIN): $(POOLTEST_OBJS)
	$(LD) -o $@ $^

pooltest: $(POOLTEST_BIN)
	./$(POOLTEST_BIN)

# --- test-only: io_uring submission accounting, against the real kernel ---
RINGTEST_BIN  = bin/linnea-ringtest
RINGTEST_OBJS = test/uring/linnea_ringtest.o src/server/linnea_ring.o \
                src/lib/linnea_print.o src/lib/linnea_string.o

test/uring/linnea_ringtest.o: test/uring/linnea_ringtest.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(RINGTEST_BIN): $(RINGTEST_OBJS)
	$(LD) -o $@ $^

ringtest: $(RINGTEST_BIN)
	./$(RINGTEST_BIN)

# --- test-only: QPACK decoder (reads a field section on stdin) ---
QPACKTEST_BIN  = bin/linnea-qpacktest
QPACKTEST_OBJS = test/quic/linnea_qpacktest.o src/server/linnea_qpack.o src/server/linnea_hpack.o \
                 src/server/linnea_static.o src/lib/linnea_string.o src/server/linnea_time.o

test/quic/linnea_qpacktest.o: test/quic/linnea_qpacktest.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(QPACKTEST_BIN): $(QPACKTEST_OBJS)
	$(LD) -o $@ $^

qpacktest: $(QPACKTEST_BIN)

# --- test-only: HTTP/3 request-stream framing (reads a stream on stdin) ---
H3TEST_BIN  = bin/linnea-h3test
H3TEST_OBJS = test/quic/linnea_h3test.o src/server/linnea_http3.o src/server/linnea_qpack.o \
              src/server/linnea_hpack.o src/lib/linnea_quic.o src/lib/linnea_quic_crypto.o \
              src/lib/linnea_aesgcm.o src/lib/linnea_sha256.o src/lib/linnea_tls_kdf.o \
              src/lib/linnea_x25519.o src/lib/linnea_fe25519.o src/server/linnea_static.o \
              src/lib/linnea_string.o src/server/linnea_time.o src/server/linnea_log.o \
              src/lib/linnea_print.o src/server/linnea_error.o src/server/linnea_config.o \
              src/server/linnea_config_parse.o src/server/linnea_network.o $(QUICP256)

test/quic/linnea_h3test.o: test/quic/linnea_h3test.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(H3TEST_BIN): $(H3TEST_OBJS)
	$(LD) -o $@ $^

h3test: $(H3TEST_BIN)

# --- test-only: HTTP/3 response builder (writes a response to stdout) ---
H3RESP_BIN  = bin/linnea-h3resp
H3RESP_OBJS = test/quic/linnea_h3resp.o src/server/linnea_http3.o src/server/linnea_qpack.o \
              src/server/linnea_hpack.o src/lib/linnea_quic.o src/lib/linnea_quic_crypto.o \
              src/lib/linnea_aesgcm.o src/lib/linnea_sha256.o src/lib/linnea_tls_kdf.o \
              src/lib/linnea_x25519.o src/lib/linnea_fe25519.o src/server/linnea_static.o \
              src/lib/linnea_string.o src/server/linnea_time.o src/server/linnea_log.o \
              src/lib/linnea_print.o src/server/linnea_error.o src/server/linnea_config.o \
              src/server/linnea_config_parse.o src/server/linnea_network.o $(QUICP256)

test/quic/linnea_h3resp.o: test/quic/linnea_h3resp.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(H3RESP_BIN): $(H3RESP_OBJS)
	$(LD) -o $@ $^

h3resp: $(H3RESP_BIN)

# --- linnea-probe build rules (product; PROBE_BIN/PROBE_OBJS defined up top) ---
src/probe/linnea_probe.o: src/probe/linnea_probe.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(PROBE_BIN): $(PROBE_OBJS)
	$(LD) -o $@ $^

probe: $(PROBE_BIN)

# Globs, not a list of the variables above. The list was one, and it had drifted
# to cover six of the twenty binaries this file can produce: `make clean` left
# linnea-h3test, linnea-pooltest, linnea-quiccv and a dozen others sitting in
# bin/ looking current, while removing the objects they were linked from. A
# stale binary that survives a clean is worse than no clean at all, and a list
# that has to be extended by hand every time a target is added will drift again.
#
# bin/ holds nothing else — its own .gitignore ignores the whole directory and
# excepts only itself — and every product is bin/linnea or bin/linnea-something,
# so naming those two patterns cannot reach .gitignore whatever the shell does
# with dotfiles. Objects are every .o under the two source trees; the generated
# crypto vectors are named because they are an .inc and not a .o.
clean:
	rm -f bin/linnea bin/linnea-*
	rm -f src/*/*.o test/*/*.o $(CRYPTO_VECS)

test: $(BIN) $(SELFTEST_BIN) $(TLSTEST_BIN) $(QUICTEST_BIN) $(QUICSRV_BIN) \
      $(QUICTP_BIN) $(QUICSH_BIN) $(QUICEE_BIN) $(QUICCERT_BIN) \
      bin/linnea-quiccv bin/linnea-quicfin bin/linnea-quichs $(QPACKTEST_BIN) \
      $(H3TEST_BIN) $(H3RESP_BIN) $(POOLTEST_BIN) $(RTXTEST_BIN) $(REPLAYTEST_BIN) \
      $(RINGTEST_BIN) $(WS_BIN)
	./test/run_tests.sh

# Install all four products to /usr/local/bin: bin_t under SELinux, so systemd
# may exec the server, and the fresh inode picks up the standard label — no
# setcap or restorecon after rebuilds. Run as root (`sudo make install`).
# Routine deploy:
#   make && sudo make install && sudo systemctl restart linnea
#
# It COPIES and does not build, so that root never compiles into the tree —
# root-owned .o files and binaries make the next ordinary `make` fail or, worse,
# quietly not rebuild. That was the stated intent before, but a prerequisite on
# the two backends undid it, which is exactly how they came to be root-owned.
#
# Copying without building can install something stale instead, so the guard
# asks make whether the tree is already built (-q builds nothing, it only
# answers) and stops with the command to run rather than deploying yesterday's
# binary. The systemd units are a one-time install; see config/*.service.
# linnea-probe is a plain CLI client — no unit, just a binary on the PATH.
install:
	@$(MAKE) -q all || { \
	    echo "linnea: the tree is not built, or is built from older sources."; \
	    echo "        run 'make' first, AS YOURSELF — this target only copies,"; \
	    echo "        so that root never leaves objects it owns in the tree."; \
	    exit 1; }
	install -m 0755 $(BIN) /usr/local/bin/linnea
	install -m 0755 $(PROBE_BIN) /usr/local/bin/linnea-probe
	install -m 0755 $(API_BIN) /usr/local/bin/linnea-api
	install -m 0755 $(WS_BIN) /usr/local/bin/linnea-ws

.PHONY: all clean test selftest tlstest probe api ws wsfast install
