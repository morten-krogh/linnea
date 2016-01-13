#include "linnea_core.h"

void linnea_core_print_diagnostics(struct state *state, const char * restrict format, ...)
{
	if (state->diagnostics) {
		va_list args;
		va_start(args, format);
		vprintf(format, args);
		va_end(args);
	}
}
