#include "linnea.h"


void linnea_core_accept_loop(struct state *state)
{
	

	
}
/*

 struct sockaddr_storage remote_addr;
        socklen_t remote_addr_len = sizeof remote_addr;

        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        while (1) {
                int *accepted_fd = malloc(sizeof(int*));
                *accepted_fd = accept(listen_fd, (struct sockaddr *) &remote_addr, &remote_addr_len);
                if (*accepted_fd == -1) {
                        perror("accept: ");
                        break;
                }

                pthread_t thread;
                pthread_create(&thread, &attr, handle_connection, accepted_fd);
                // pthread_create(pthread_t *restrict thread, const pthread_attr_t *restrict attr, void *(*start_routine)(void *), void *restrict arg);                                                                                        
        }

*/
