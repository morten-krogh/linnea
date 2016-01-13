#ifndef LINNEA_CORE_H
#define LINNEA_CORE_H

#include "linnea_stdlib.h"

struct state {
	bool diagnostics;
	void *app_state;
	int ai_family;
	char *hostname;
	char *servname;
	int listen_fd;
};

void *linnea_core_malloc(size_t size);
void linnea_core_init(void);
void linnea_core_print_diagnostics(struct state *state, const char * restrict format, ...);
void linnea_core_listen(struct state *state);
void linnea_core_accept_loop(struct state *state);


#endif
