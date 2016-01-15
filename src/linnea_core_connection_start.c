#include "linnea.h"

void *linnea_core_connection_start(void *arg)
{
	struct state_and_connection *state_and_connection = (struct state_and_connection*) arg;

	struct state *state = state_and_connection->state;
	struct connection *connection = state_and_connection->connection;

	free(state_and_connection);

	linnea_cb_connection_init(state, connection);

	
	
	while (true) {

		sleep(5);
	}
	
	

	return NULL;
}
