#include "linnea_core.h"

void linnea_core_print_diagnostics(struct state *state, char *message)
{
	if (state->diagnostics) {
		printf("%s\n", message);
	}
}
