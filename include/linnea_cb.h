#ifndef LINNEA_CB_H
#define LINNEA_CB_H

#include "linnea_stdlib.h"

void linnea_cb_init(struct state *state);
void linnea_cb_get_address(struct state *state);
void linnea_cb_server_started_listening(struct state* state);
void linnea_cb_connection_init(struct state *state, struct connection *connection);


#endif
