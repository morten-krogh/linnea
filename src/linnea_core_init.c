#include "linnea.h"

void linnea_core_init(int argc, char **argv)
{
	struct state *state = linnea_core_malloc(sizeof *state);

	state->argc = argc;
	state->argv = argv;
	
	state->diagnostics = true;
	linnea_cb_init(state);
	linnea_core_print_diagnostics(state, "linnea_cb_init() was called. Diagnostics is printed to standard output because state->diagnostics = true. state->diagnostics can be changed at any time\n");

	linnea_cb_get_address(state);
	linnea_core_print_diagnostics(state, "linnea_cb_get_address() was called to get the ip-protocol, ip-address and port of the server.\n");

	linnea_core_listen(state);
	linnea_cb_server_started_listening(state);
	
	linnea_core_accept_loop(state);
}
