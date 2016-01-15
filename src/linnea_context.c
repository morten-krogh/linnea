#include <stddef.h>
#include <poll.h>

#include "linnea_context.h"




void linnea_context_start_event_loop(struct linnea_context *context)
{
	for (;;) {
		poll(NULL, 0, context->event_loop_timeout);

		context->handler_event_loop_timeout(context);
	}
	

}
