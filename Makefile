cflags := -std=c11 -g -Wpedantic -O0

cc := $(CC)

src-dir = src
include-dir = include
lib-dir = lib

sources := $(wildcard $(src-dir)/*.c)
includes := $(wildcard $(include-dir)/*.h)

target-objects := $(patsubst %.c, $(lib-dir)/%.o, $(notdir $(sources)))
current-objects := $(wildcard $(lib-dir)/*.o)
stale-objects = $(filter-out $(target-objects), $(current-objects))

all: clean-stale-objects $(target-objects)

rebuild: clean all

$(lib-dir)/%.o: $(src-dir)/%.c $(includes)
	$(cc) $(cflags) -I$(include-dir) -c -o $@ $<

.PHONY: clean clean-stale-objects

clean:
	@for file in $(current-objects); do echo "rm $$file"; rm $$file; done

clean-stale-objects:
	@for file in $(stale-objects); do echo "rm $$file"; rm $$file; done

print-%  : ; @echo $* = $($*)
