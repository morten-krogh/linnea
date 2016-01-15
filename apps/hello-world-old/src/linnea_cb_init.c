#include "linnea.h"
#include "app.h"

void linnea_cb_init(struct state *state)
{
	state->diagnostics = true;
	
	struct app_state *app_state = linnea_core_malloc(sizeof *app_state);
	app_state->message = "Hello world!";
	app_state->counter = 0;

	state->app_state = app_state;
}
