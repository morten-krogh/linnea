#include "linnea_core.h"
#include "linnea_cb.h"

int main(void)
{
	struct core_state *core_state = malloc(sizeof *core_state);
	core_state->app_state = linnea_cb_app_state_init();
	
	
	return 0;
}
