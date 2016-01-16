


#include "linnea_socket.h"
#include "linnea_buffer.h"

struct linnea_socket *linnea_socket_init(struct linnea_socket *linnea_socket, int fd) {
	linnea_socket->fd = fd;
	linnea_socket->closed = false;
	linnea_socket->state = listener;
	linnea_buffer_init(&linnea_socket->in_buffer, 1000);
	linnea_buffer_init(&linnea_socket->out_buffer, 1000);
	linnea_socket->max_in_buffer_size = 100000;

	return linnea_socket;
}

void linnea_socket_free(struct linnea_socket *linnea_socket)
{
	linnea_buffer_free(&linnea_socket->in_buffer);
	linnea_buffer_free(&linnea_socket->out_buffer);
}
