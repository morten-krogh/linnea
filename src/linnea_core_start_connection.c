#include "linnea.h"

void *linnea_core_start_connection(void *arg)
{
	struct state_and_connection *state_and_connection = (struct state_and_connection*) arg;

	struct state *state = state_and_connection->state;
	struct connection *connection = state_and_connection->connection;

	free(state_and_connection);

	int accepted_fd = connection->accepted_fd;

	while (true) {
		printf("accepted_fd = %d\n", accepted_fd);
		sleep(5);
	}
	
	

	return NULL;
}
