#ifndef LINNEA_CORE_H
#define LINNEA_CORE_H

#include "linnea_stdlib.h"
#include "linnea_state.h"

void *linnea_core_malloc(size_t size);
void linnea_core_init(int argc, char **argv);
void linnea_core_print_diagnostics(struct state *state, const char * restrict format, ...);
void linnea_core_listen(struct state *state);
void linnea_core_accept_loop(struct state *state);
void *linnea_core_start_connection(void *arg);

#endif
