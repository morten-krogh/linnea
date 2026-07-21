NASM      = nasm
NASMFLAGS = -f elf64 -g -F dwarf -I include/
LD        = ld

SRCS = $(wildcard src/*.asm)
OBJS = $(SRCS:.asm=.o)
INCS = $(wildcard include/*.inc)
BIN  = bin/linnea

# liburing is vendored (lib/ is gitignored) and built statically without
# libc (nolibc is the default on x86-64 since liburing 2.15).
LIBURING_TAG = liburing-2.15
LIBURING_DIR = lib/liburing
LIBURING_A   = $(LIBURING_DIR)/src/liburing.a

all: $(BIN)

$(BIN): $(OBJS) $(LIBURING_A)
	$(LD) -o $@ $(OBJS) $(LIBURING_A)

$(LIBURING_A):
	test -d $(LIBURING_DIR) || git clone --depth 1 -b $(LIBURING_TAG) https://github.com/axboe/liburing.git $(LIBURING_DIR)
	cd $(LIBURING_DIR) && ./configure > /dev/null
	$(MAKE) -C $(LIBURING_DIR)/src

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

# --- QUIC crypto known-answer tests (own _start; RFC 9001 vectors) ---
QUICTEST_BIN  = bin/linnea-quictest
QUICTEST_OBJS = test/quic/linnea_quictest.o src/linnea_quic_crypto.o \
                src/linnea_quic.o src/linnea_aesgcm.o src/linnea_sha256.o \
                src/linnea_tls_kdf.o src/linnea_x25519.o src/linnea_fe25519.o \
                src/linnea_print.o src/linnea_string.o

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
               src/linnea_print.o src/linnea_string.o

test/quic/linnea_quicserver.o: test/quic/linnea_quicserver.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(QUICSRV_BIN): $(QUICSRV_OBJS)
	$(LD) -o $@ $^

quicserver: $(QUICSRV_BIN)

# --- test-only: emit encoded QUIC transport parameters for aioquic to parse ---
QUICTP_BIN  = bin/linnea-quictp
QUICTP_OBJS = test/quic/linnea_quictp.o src/linnea_quic.o src/linnea_quic_crypto.o \
              src/linnea_aesgcm.o src/linnea_sha256.o src/linnea_tls_kdf.o \
              src/linnea_x25519.o src/linnea_fe25519.o

test/quic/linnea_quictp.o: test/quic/linnea_quictp.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(QUICTP_BIN): $(QUICTP_OBJS)
	$(LD) -o $@ $^

quictp: $(QUICTP_BIN)

# --- test-only: emit a QUIC ServerHello for aioquic's TLS parser ---
QUICSH_BIN  = bin/linnea-quicsh
QUICSH_OBJS = test/quic/linnea_quicsh.o src/linnea_quic.o src/linnea_quic_crypto.o \
              src/linnea_aesgcm.o src/linnea_sha256.o src/linnea_tls_kdf.o \
              src/linnea_x25519.o src/linnea_fe25519.o

test/quic/linnea_quicsh.o: test/quic/linnea_quicsh.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(QUICSH_BIN): $(QUICSH_OBJS)
	$(LD) -o $@ $^

quicsh: $(QUICSH_BIN)

# --- test-only: emit a QUIC EncryptedExtensions for aioquic's TLS parser ---
QUICEE_BIN  = bin/linnea-quicee
QUICEE_OBJS = test/quic/linnea_quicee.o src/linnea_quic.o src/linnea_quic_crypto.o \
              src/linnea_aesgcm.o src/linnea_sha256.o src/linnea_tls_kdf.o \
              src/linnea_x25519.o src/linnea_fe25519.o

test/quic/linnea_quicee.o: test/quic/linnea_quicee.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(QUICEE_BIN): $(QUICEE_OBJS)
	$(LD) -o $@ $^

quicee: $(QUICEE_BIN)

clean:
	rm -f $(OBJS) $(BIN) $(SELFTEST_BIN) $(TLSTEST_BIN) $(QUICTEST_BIN) \
	      test/crypto/*.o test/tls/*.o test/quic/*.o $(CRYPTO_VECS)

test: $(BIN) $(SELFTEST_BIN) $(TLSTEST_BIN) $(QUICTEST_BIN) $(QUICSRV_BIN) \
      $(QUICTP_BIN) $(QUICSH_BIN) $(QUICEE_BIN)
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
