#ifndef LINNEA_CORE_H
#define LINNEA_CORE_H

#include "linnea_stdlib.h"

struct state {
	bool diagnostics;
	void *app_state;
	int ai_family;
	char *hostname;
	char *servname;
	
};

void *linnea_core_malloc(size_t size);
void linnea_core_init(void);
void linnea_core_print_diagnostics(struct state *state, char *message);
void linnea_core_listen(struct state *state);
	

#endif
