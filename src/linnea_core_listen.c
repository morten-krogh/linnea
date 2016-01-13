#include "linnea.h"

void linnea_core_listen(struct state *state)
{
	struct addrinfo hints;

	memset(&hints, 0, sizeof hints);
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = state->ai_family;
	hints.ai_socktype = SOCK_STREAM;

	struct addrinfo *res;
	int status;
	if ((status = getaddrinfo(state->hostname, state->servname, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
		exit(1);
	}

	state->listen_fd = -1;
	struct addrinfo *addrinfo;
	for (addrinfo = res; addrinfo != NULL; addrinfo = addrinfo->ai_next) {
		if ((state->listen_fd = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol)) == -1) {
			perror("socket: ");
			continue;
		}

		if (bind(state->listen_fd, addrinfo->ai_addr, addrinfo->ai_addrlen) == -1) {
			close(state->listen_fd);
			perror("bind: ");
			continue;
		}

		break;
	}

	if (addrinfo == NULL) {
		fprintf(stderr, "Check that the port is not in use and that the process has the right permission\n");
		exit(1);
	}

	state->ai_family = addrinfo->ai_family;
	if (addrinfo->ai_family == PF_INET) {
		struct sockaddr_in *sa = (struct sockaddr_in *) addrinfo->ai_addr;
		unsigned short sin_port = ntohs(sa->sin_port);
		unsigned long s_addr = sa->sin_addr.s_addr;

		char dst[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &s_addr, dst, INET_ADDRSTRLEN);
		
		printf("ipv4, port = %d, addr = %s\n", sin_port, dst);
		
		
		
	} else if (addrinfo->ai_family == PF_INET6) {
		printf("ipv6\n");
	}
	
	freeaddrinfo(res);





	
	int backlog = 20;
	if (listen(state->listen_fd, 10) == -1) {
		perror("Error in listen(): ");
		exit(1);
	}
	linnea_core_print_diagnostics(state, "The server is listening at address %s, port %s\n", state->hostname, state->servname);
}
