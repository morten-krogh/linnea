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
                src/linnea_sha512.o src/linnea_fe25519.o src/linnea_x25519.o \
                src/linnea_ed25519.o src/linnea_aesgcm.o src/linnea_print.o \
                src/linnea_string.o
CRYPTO_VECS   = test/crypto/sha256_vectors.inc

$(CRYPTO_VECS): test/crypto/gen_vectors.py
	python3 $< > $@

test/crypto/linnea_selftest.o: test/crypto/linnea_selftest.asm $(INCS) $(CRYPTO_VECS)
	$(NASM) $(NASMFLAGS) -I test/crypto/ -o $@ $<

$(SELFTEST_BIN): $(SELFTEST_OBJS)
	$(LD) -o $@ $^

selftest: $(SELFTEST_BIN)
	./$(SELFTEST_BIN)

clean:
	rm -f $(OBJS) $(BIN) $(SELFTEST_BIN) test/crypto/*.o $(CRYPTO_VECS)

test: $(BIN) $(SELFTEST_BIN)
	./test/run_tests.sh

.PHONY: all clean test selftest
