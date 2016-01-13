#include "linnea.h"

void linnea_core_accept_loop(struct state *state)
{
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	while (true) {
		struct sockaddr_storage remote_addr;
		socklen_t remote_addr_len = sizeof remote_addr;

		int accepted_fd = accept(state->listen_fd, (struct sockaddr *) &remote_addr, &remote_addr_len);
		if (accepted_fd == -1) continue;

		struct connection *connection = linnea_core_malloc(sizeof *connection);
		connection->accepted_fd = accepted_fd;
		connection->remote_addr = remote_addr;
		connection->remote_addr_len = remote_addr_len;

		struct state_and_connection *state_and_connection = linnea_core_malloc(sizeof *state_and_connection);
		state_and_connection->state = state;
		state_and_connection->connection = connection;
		
		pthread_t thread;
		if (pthread_create(&thread, &attr, linnea_core_start_connection, state_and_connection) != 0) {
			close(accepted_fd);
		}
	}
}
