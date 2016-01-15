#ifndef LINNEA_STATE_H
#define LINNEA_STATE_H

struct state {
	int argc;
	char **argv;
	bool diagnostics;
	void *app_state;
	int ai_family;
	char *hostname;
	char *port;
	int listen_fd;
};

struct connection {
	int accepted_fd;
	struct sockaddr_storage remote_addr;
	socklen_t remote_addr_len;
	void* app_connection_state;
	
	




};

/*
  struct state_and_connection is used to transfer both state and connection to a 
  new thread by create_thread. A single void* is needed.
*/

struct state_and_connection {
	struct state *state;
	struct connection *connection;
};


#endif
