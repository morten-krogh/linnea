#include "linnea.h"

void linnea_core_init(void)
{
	struct state *state = linnea_core_malloc(sizeof *state);

	state->diagnostics = linnea_cb_should_print_diagnostics();
	linnea_core_print_diagnostics(state, "Printing of diagnostics turned on by linnea_cb_should_print_diagnostics().\n");

	state->app_state = linnea_cb_app_state_init();
	linnea_core_print_diagnostics(state, "linnea_cb_app_state_init() was called.\n");

	linnea_cb_get_address(state->app_state, &state->ai_family, &state->hostname, &state->servname);
	linnea_core_print_diagnostics(state, "linnea_cb_get_address() was called to get the ip-protocol, ip-address and port of the server.\n");

	linnea_core_listen(state);
	linnea_cb_server_started_listening(state->app_state, state->ai_family, state->hostname, state->servname);
	
	linnea_core_accept_loop(state);
}
