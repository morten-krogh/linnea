#include "linnea.h"

void linnea_core_listen(struct state *state)
{
	struct addrinfo hints;

	memset(&hints, 0, sizeof hints);
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = state->ai_family;
	hints.ai_socktype = SOCK_STREAM;

	struct addrinfo *addrinfo_res;
	int status;
	if ((status = getaddrinfo(state->hostname, state->servname, &hints, &addrinfo_res)) != 0) {
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
		exit(1);
	}
	
	if ((state->listen_fd = socket(addrinfo_res->ai_family, addrinfo_res->ai_socktype, addrinfo_res->ai_protocol)) == -1) {
		fprintf(stderr, "Error in socket()\n");
		exit(1);
	}
	
	if (bind(state->listen_fd, addrinfo_res->ai_addr, addrinfo_res->ai_addrlen) == -1) {
		perror("Error in bind(): ");
		fprintf(stderr, "Check that the port is not in use and that the process has the right permission\n");
		exit(1);
	}

	freeaddrinfo(addrinfo_res);

	int backlog = 20;
	if (listen(state->listen_fd, 10) == -1) {
		perror("Error in listen(): ");
		exit(1);
	}
	linnea_core_print_diagnostics(state, "The server is listening at address %s, port %s\n", state->hostname, state->servname);



}
