#ifndef LUNNEA_NETWORK_H
#define LUNNEA_NETWORK_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/*                                                                                                                                                                                                                                                                            * linnea_create_listener create a listening socket.                                                                                                                                                                                                                          * The arguments are:                                                                                                                                                                                                                                                         *   ai_family descrbes the ip family and can be one of PF_UNSPEC, PF_INET or PF_INET6 for unspecified, ipv4, or ipv6.                                                                                                                                                        *   hostname is the ip address or host name of the server. It can be set to NULL.                                                                                                                                                                                            *   servname can be the port, e.g. "80".                                                                                                                                                                                                                                     * The three first arguments are used in getaddrinfo. See the man page for getaddrinfo to obtain full information.                                                                                                                                                            *  socket_addr is a return argument. It contains the actual bound address of the socket in case of success.                                                                                                                                                                  *  If socket_addr is NULL, the aegument is ignored.                                                                                                                                                                                                                          *  The return value is the file descriptor of the listening socket if successful. In case of failure, the return value is -1.                                                                                                                                                * The function logs the reason for failure to stderr.                                                                                                                                                                                                                        */
int linnea_network_create_listener(const int ai_family, const char *hostname, const char *servname, struct sockaddr *socket_addr);









#endif
