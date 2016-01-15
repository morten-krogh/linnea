cflags := -std=c11 -g -Wpedantic -O0

ldflags :=
ldlibs := 
target_arch :=
cc := $(CC)

linnea-include-dir := $(realpath ../../include)
linnea-lib-dir := $(realpath ../../lib)
linnea-archive := liblinnea.a

hello-world: hello-world.c
	$(cc) -I$(linnea-include-dir) -L$(linnea-lib-dir) -llinnea -o hello-world hello-world.c 

.PHONY: clean

clean:
	rm hello-world
