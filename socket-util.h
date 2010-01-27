/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foosocketutilhfoo
#define foosocketutilhfoo

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <net/if.h>

#include "macro.h"
#include "util.h"

typedef struct SocketAddress {
        union {
                struct sockaddr sa;
                struct sockaddr_in in4;
                struct sockaddr_in6 in6;
                struct sockaddr_un un;
                struct sockaddr_storage storage;
        } sockaddr;

        /* We store the size here explicitly due to the weird
         * sockaddr_un semantics for abstract sockets */
        socklen_t size;

        /* Socket type, i.e. SOCK_STREAM, SOCK_DGRAM, ... */
        int type;
} SocketAddress;

typedef enum SocketAddressBindIPv6Only {
        SOCKET_ADDRESS_DEFAULT,
        SOCKET_ADDRESS_BOTH,
        SOCKET_ADDRESS_IPV6_ONLY
} SocketAddressBindIPv6Only;

#define socket_address_family(a) ((a)->sockaddr.sa.sa_family)

int socket_address_parse(SocketAddress *a, const char *s);
int socket_address_print(const SocketAddress *a, char **p);
int socket_address_verify(const SocketAddress *a);
int socket_address_listen(const SocketAddress *a, int backlog, SocketAddressBindIPv6Only only, const char *bind_to_device, int *ret);

#endif
