#include "linnea.h"
#include "app.h"

void *linnea_cb_app_state_init(void)
{
	struct app_state *app_state = linnea_core_malloc(sizeof *app_state);
	app_state->message = "Hello world!";
	app_state->counter = 0;
	
	return app_state;
}
