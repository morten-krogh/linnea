#include "linnea.h"

void linnea_cb_get_address(struct state *state)
{
	state->ai_family = PF_INET;
	state->hostname = "localhost";
	state->port = "9000";
}
