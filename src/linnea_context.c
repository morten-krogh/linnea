#include <stddef.h>
#include <poll.h>

#include "linnea_context.h"

struct linnea_context *linnea_context_init(struct linnea_context *context)
{
	context->event_loop_timeout = 1000;

	return context;
}

void linnea_context_start_event_loop(struct linnea_context *context)
{
	for (;;) {
		

		poll(NULL, 0, context->event_loop_timeout);

		context->handler_event_loop_timeout(context);
	}
	

}
