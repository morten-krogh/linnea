#include "linnea.h"

void linnea_cb_connection_init(struct state *state, struct connection *connection)
{

	linnea_core_connection_recv(state, connection);
}
