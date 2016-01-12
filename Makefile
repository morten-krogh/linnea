cflags := -Wall

src-dir := src
include-dir := include
lib-dir := lib

sources := $(wildcard $(src-dir)/*.c)
includes := $(wildcard $(include-dir)/*.h)
target-objects := $(patsubst $(src-dir)%.c, $(lib-dir)%.o, $(sources))

current-objects := $(wildcard $(lib-dir)/*.o)
additional-objects = $(filter-out $(target-objects), $(current-objects))

all: clean-additional-objects $(target-objects)

$(lib-dir)/%.o: $(src-dir)/%.c $(includes)
	cc $(CFLAGS) -I$(include-dir) -c -o $@ $<

.PHONY: clean clean-additional-objects

clean:
	@for file in $(current-objects); do echo "rm $$file"; rm $$file; done

clean-additional-objects:
	@for file in $(additional-objects); do echo "rm $$file"; rm $$file; done

print-%  : ; @echo $* = $($*)
