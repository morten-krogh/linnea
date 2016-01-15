#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "linnea_network.h"



int linnea_create_listener(const int ai_family, const char *hostname, const char *servname, struct sockaddr *socket_addr)
{
	struct addrinfo hints;

	memset(&hints, 0, sizeof hints);
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = ai_family;
	hints.ai_socktype = SOCK_STREAM;

	struct addrinfo *res;
	int status;
	
	if ((status = getaddrinfo(hostname, servname, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
		return -1;
	}

	int listen_fd = -1;
	struct addrinfo *addrinfo;
	for (addrinfo = res; addrinfo != NULL; addrinfo = addrinfo->ai_next) {
		if ((listen_fd = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol)) == -1) {
			perror("socket: ");
			continue;
		}

		int socket_option_value = 1;
		setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &socket_option_value, sizeof(int));
		
		if (bind(listen_fd, addrinfo->ai_addr, addrinfo->ai_addrlen) == -1) {
			close(listen_fd);
			perror("bind: ");
			continue;
		}

		break;
	}

	if (addrinfo == NULL) {
		fprintf(stderr, "Check that the host and port are correct, that the port is not used by another process and that the process has the right permission\n");
		return -1;
	}

	if (socket_addr != NULL) {
		*socket_addr = *addrinfo->ai_addr;
	}

	freeaddrinfo(res);
	
	int backlog = 20;
	if (listen(listen_fd, backlog) == -1) {
		perror("Error in listen(): ");
		return -1;
	}

	return listen_fd;
}

/*
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
		if (pthread_create(&thread, &attr, linnea_core_connection_start, state_and_connection) != 0) {
			close(accepted_fd);
			free(connection);
			free(state_and_connection);
		}
	}
}
*/
