/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foosocketutilhfoo
#define foosocketutilhfoo

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>

#include "macro.h"
#include "util.h"

typedef struct Address {
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

        /* Only for INET6 sockets: issue IPV6_V6ONLY sockopt */
        bool bind_ipv6_only;
} Address;

#define address_family(a) ((a)->sockaddr.sa.sa_family)

int address_parse(Address *a, const char *s);
int address_print(const Address *a, char **p);
int address_verify(const Address *a);
int address_listen(const Address *a, int backlog);

#endif
