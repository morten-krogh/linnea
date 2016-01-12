#include "linnea.h"

int main(void)
{
	struct core_state *core_state = linnea_util_malloc(sizeof *core_state);
	core_state->app_state = linnea_cb_app_state_init();
	
	
	return 0;
}
