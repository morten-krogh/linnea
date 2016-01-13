#ifndef LINNEA_CB_H
#define LINNEA_CB_H

#include "linnea_stdlib.h"

bool linnea_cb_should_print_diagnostics(void);
void *linnea_cb_app_state_init(void);
void linnea_cb_get_address(void *app_state, int *ai_family, char **hostname, char **servname);
void linnea_cb_server_started_listening(void *app_state, int ai_family, char *hostname, char *servname);


#endif
