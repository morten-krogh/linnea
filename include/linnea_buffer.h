#ifndef LINNEA_BUFFER_H
#define LINNEA_BUFFER_H

struct linnea_buffer {
	char *chars;
	size_t start;
	size_t len;
	size_t cap;
};

struct linnea_buffer *linnea_buffer_init(struct linnea_buffer *buf, size_t capacity);
void linnea_buffer_free(struct linnea_buffer *buf);
struct linnea_buffer *linnea_buffer_resize(struct linnea_buffer *buf, size_t capacity);
struct linnea_buffer *linnea_buffer_append(struct linnea_buffer *buf, const char *data, size_t len); 
int linnea_buffer *linnea_buffer_print(const struct linnea_buffer *buf); 

#endif
