/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "list.h"
#include "socket-util.h"
#include "timesyncd-forward.h"

#define DEFAULT_NTP_PORT 123

typedef enum ServerType {
        SERVER_SYSTEM,
        SERVER_FALLBACK,
        SERVER_LINK,
        SERVER_RUNTIME,
        _SERVER_TYPE_MAX,
        _SERVER_TYPE_INVALID = -EINVAL,
} ServerType;

struct ServerAddress {
        ServerName *name;

        union sockaddr_union sockaddr;
        socklen_t socklen;

        LIST_FIELDS(ServerAddress, addresses);
};

struct ServerName {
        Manager *manager;

        bool marked;

        ServerType type;
        char *string;   /* canonical server specification, including a non-default port */
        char *host;     /* host name or address without port, as passed to getaddrinfo() */
        uint16_t port;  /* UDP port to use */

        LIST_HEAD(ServerAddress, addresses);
        LIST_FIELDS(ServerName, names);
};

int server_address_new(ServerName *n, ServerAddress **ret, const union sockaddr_union *sockaddr, socklen_t socklen);
ServerAddress* server_address_free(ServerAddress *a);
static inline int server_address_pretty(ServerAddress *a, char **pretty) {
        return sockaddr_pretty(&a->sockaddr.sa, a->socklen, true, true, pretty);
}

int server_name_parse(const char *s, char **ret_host, uint16_t *ret_port);
int server_name_new(Manager *m, ServerName **ret, ServerType type, const char *host, uint16_t port);
ServerName *server_name_free(ServerName *n);
void server_name_flush_addresses(ServerName *n);
