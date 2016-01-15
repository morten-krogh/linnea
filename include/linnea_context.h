#ifndef LINNEA_CONTEXT_H
#define LINNEA_CONTEXT_H

struct linnea_context;
struct linnea_connection;

typedef void (*context_handler_type)(struct linnea_context *context);
typedef void (*context_connection_handler_type)(struct linnea_context *context, struct linnea_connection *connection);


struct linnea_context {
	int event_loop_timeout;
	context_handler_type handler_event_loop_timeout;
	context_connection_handler_type handler_connection_accepted;
	

};

void linnea_context_start_event_loop(struct linnea_context *context);





#endif
