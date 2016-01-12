#include "linnea_core.h"
#include "linnea_cb.h"
#include "app.h"

void *linnea_cb_app_state_init(void)
{
	struct app_state *app_state = malloc(sizeof *app_state);
	app_state->message = "Hello world!";
	app_state->counter = 0;
	
	return app_state;
}
