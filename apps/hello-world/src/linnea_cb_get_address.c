#include "linnea.h"

void linnea_cb_get_address(void *app_state, int *ai_family, char **hostname, char **servname)
{
	*ai_family = PF_INET; 
	*hostname = NULL;
	*servname = "9000";
}
