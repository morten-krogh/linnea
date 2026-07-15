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

clean:
	rm -f $(OBJS) $(BIN)

test: $(BIN)
	./test/run_tests.sh

.PHONY: all clean test
