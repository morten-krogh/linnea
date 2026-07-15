NASM      = nasm
NASMFLAGS = -f elf64 -g -F dwarf -I include/
LD        = ld

SRCS = $(wildcard src/*.asm)
OBJS = $(SRCS:.asm=.o)
INCS = $(wildcard include/*.inc)
BIN  = bin/linnea

all: $(BIN)

$(BIN): $(OBJS)
	$(LD) -o $@ $(OBJS)

src/%.o: src/%.asm $(INCS)
	$(NASM) $(NASMFLAGS) -o $@ $<

clean:
	rm -f $(OBJS) $(BIN)

test: $(BIN)
	./test/run_tests.sh

.PHONY: all clean test
