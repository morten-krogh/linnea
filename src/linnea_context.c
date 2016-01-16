#include <stddef.h>
#include <poll.h>

#include "linnea_context.h"
#include "linnea_network.h"

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

int linnea_context_add_listener(struct linnea_context *context, const int ai_family, const char *hostname, const char *servname)
{
	int fd;
	if ((fd = linnea_network_create_listener(ai_family, hostname, servname, NULL)) == -1) return -1;

	
	
	

	return fd;
}
