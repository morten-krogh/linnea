#ifndef LINNEA_CONTEXT_H
#define LINNEA_CONTEXT_H

#include "linnea_socket.h"

struct linnea_context;

typedef void (*context_handler_type)(struct linnea_context *context);
typedef void (*context_socket_handler_type)(struct linnea_context *context, struct linnea_socket *socket);


struct linnea_context {
	int event_loop_timeout; 
	context_handler_type handler_event_loop_timeout;
	context_socket_handler_type handler_socket_accepted;


};

struct linnea_context *linnea_context_init(struct linnea_context *context);
void linnea_context_start_event_loop(struct linnea_context *context);



/* linnea_context_add_listener creates a listening socket. The ai_family, hostname, and servname are decribed in linnea_network.h
 * The return value is the file descriptor of the new listening socket or -1 in case of failure. 
 */
int linnea_context_add_listener(struct linnea_context *context, const int ai_family, const char *hostname, const char *servname);





#endif
