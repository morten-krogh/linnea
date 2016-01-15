#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "linnea_buffer.h"


struct linnea_buffer *linnea_buffer_init(struct linnea_buffer *buf, size_t capacity){
	buf->data = NULL;
	buf->start = 0;
	buf->len = 0;
	buf->cap = 0;
	linnea_buffer_resize(buf, capacity);
	return buf;
}

void linnea_buffer_free(struct linnea_buffer *buf)
{
	free(buf->data);
	linnea_buffer_init(buf, 0);
}

static void linnea_buffer_move(struct linnea_buffer *buf)
{
	if (buf->start != 0) {
		memmove(buf->data, buf->data + buf->start, buf->len);
		buf->start = 0;
	}
}

struct linnea_buffer *linnea_buffer_resize(struct linnea_buffer *buf, size_t capacity)
{
	if (capacity < buf->len || buf->cap == capacity) return buf;

	linnea_buffer_move(buf);

	char *realloced_data = (char *) realloc(buf->data, capacity);
	if (realloced_data == NULL) return buf;

	buf->data = realloced_data;
	buf->cap = capacity;
	return buf;
}

struct linnea_buffer* linnea_buffer_append(struct linnea_buffer *buf, const char *data, size_t len)
{
	if (buf->len + len > buf->cap) {
		linnea_buffer_resize(buf, buf->len + len);
	} else if (buf->start + buf->len + len > buf->cap) {
		linnea_buffer_move(buf);
	}

	memcpy(buf->data + buf->start + buf->len, data, len);

	return buf;
}

int linnea_buffer_print(const struct linnea_buffer *buf)
{
	return printf("%.*s", (int) buf->len, buf->data + buf->start);
}
