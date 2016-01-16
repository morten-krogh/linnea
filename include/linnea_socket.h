#ifndef LINNEA_SOCKET_H
#define LINNEA_SOCKET_H

#include <stdbool.h>

#include "linnea_buffer.h"

enum linnea_socket_state {
	listener,
	http,

};

struct linnea_socket {
	int fd;
	bool closed;
	enum linnea_socket_state state;
	struct linnea_buffer in_buffer;
	struct linnea_buffer out_buffer;
	size_t max_in_buffer_size;
};

struct linnea_sockets {
	struct linnea_socket *data;
	size_t len;
	size_t cap;
};

struct linnea_socket *linnea_socket_init(struct linnea_socket *socket, int fd);
void linnea_socket_free(struct linnea_socket *socket);

struct linnea_sockets *linnea_sockets_init(struct linnea_sockets *sockets);





#endif
