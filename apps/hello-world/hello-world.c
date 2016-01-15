#include <stdio.h>

#include "linnea_context.h"


void handler_event_loop_timeout(struct linnea_context *context)
{
	printf("Timeout\n");
}

int main(void)
{
	struct linnea_context context;
	linnea_context_init(&context);

	context.handler_event_loop_timeout = handler_event_loop_timeout;
	
	linnea_context_start_event_loop(&context);
	
}
