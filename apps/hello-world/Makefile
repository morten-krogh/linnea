cflags := -std=c11 -g -Wpedantic -O0

ldflags :=
ldlibs := -lpthread
target_arch :=
cc := $(CC)

linnea-src-dir := $(realpath ../../src)
linnea-include-dir := $(realpath ../../include)

app-src-dir := src
app-include-dir := include

lib-dir := lib
bin-dir := bin

sources := $(wildcard $(linnea-src-dir)/*.c) $(wildcard $(app-src-dir)/*.c)
includes := $(wildcard $(linnea-include-dir)/*.h) $(wildcard $(app-include-dir)/*.h)

target-objects := $(patsubst %.c, $(lib-dir)/%.o, $(notdir $(sources)))
current-objects := $(wildcard $(lib-dir)/*.o)
stale-objects = $(filter-out $(target-objects), $(current-objects))

server := bin/server

vpath %.c $(linnea-src-dir) $(app-src-dir)

all: clean-stale-objects $(server)

rebuild: clean all

$(server): $(target-objects)
	$(cc) $(ldlibs) $(target-objects) -o $(server)

$(lib-dir)/%.o: %.c $(includes)
	$(cc) $(cflags) -I$(linnea-include-dir) -I$(app-include-dir) -c -o $@ $<

.PHONY: clean clean-stale-objects

clean:
	@for file in $(wildcard $(server)); do echo "rm $$file"; rm $$file; done 
	@for file in $(current-objects); do echo "rm $$file"; rm $$file; done

clean-stale-objects:
	@for file in $(stale-objects); do echo "rm $$file"; rm $$file; done

print-%  : ; @echo $* = $($*)
