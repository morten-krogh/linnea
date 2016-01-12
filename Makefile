cflags := -Wall

src_dir := src
include_dir := include
lib_dir := lib

sources := $(wildcard $(src_dir)/*.c)
includes := $(wildcard $(include_dir)/*.h)
target_objects := $(patsubst $(src_dir)%.c, $(lib_dir)%.o, $(sources))

all: $(target_objects)

$(lib_dir)/%.o: $(src_dir)/%.c $(includes)
	cc $(CFLAGS) -c -o $@ $<


.PHONY: clean
clean:
	-rm lib/* 

print-%  : ; @echo $* = $($*)
