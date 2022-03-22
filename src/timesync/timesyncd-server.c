/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "string-table.h"
#include "timesyncd-server.h"

static const char * const server_type_table[_SERVER_TYPE_MAX] = {
        [SERVER_SYSTEM]   = "system",
        [SERVER_FALLBACK] = "fallback",
        [SERVER_LINK]     = "link",
        [SERVER_RUNTIME]  = "runtime",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(server_type, ServerType);

int server_address_new(
                ServerName *n,
                ServerAddress **ret,
                const union sockaddr_union *sockaddr,
                socklen_t socklen) {

        ServerAddress *a, *tail;

        assert(n);
        assert(sockaddr);
        assert(socklen >= offsetof(struct sockaddr, sa_data));
        assert(socklen <= sizeof(union sockaddr_union));

        a = new(ServerAddress, 1);
        if (!a)
                return -ENOMEM;

        *a = (ServerAddress) {
                .name = n,
                .socklen = socklen,
        };

        memcpy(&a->sockaddr, sockaddr, socklen);

        LIST_FIND_TAIL(addresses, n->addresses, tail);
        LIST_INSERT_AFTER(addresses, n->addresses, tail, a);

        if (ret)
                *ret = a;

        return 0;
}

ServerAddress* server_address_free(ServerAddress *a) {
        if (!a)
                return NULL;

        if (a->name) {
                LIST_REMOVE(addresses, a->name->addresses, a);

                if (a->name->manager && a->name->manager->current_server_address == a)
                        manager_set_server_address(a->name->manager, NULL);
        }

        return mfree(a);
}

int server_name_new(
                Manager *m,
                ServerName **ret,
                ServerType type,
                const char *string) {

        ServerName *n;

        assert(m);
        assert(string);

        n = new(ServerName, 1);
        if (!n)
                return -ENOMEM;

        *n = (ServerName) {
                .manager = m,
                .type = type,
                .string = strdup(string),
        };

        if (!n->string) {
                free(n);
                return -ENOMEM;
        }

        switch (type) {
        case SERVER_SYSTEM:
                LIST_APPEND(names, m->system_servers, n);
                break;
        case SERVER_LINK:
                LIST_APPEND(names, m->link_servers, n);
                break;
        case SERVER_FALLBACK:
                LIST_APPEND(names, m->fallback_servers, n);
                break;
        case SERVER_RUNTIME:
                LIST_APPEND(names, m->runtime_servers, n);
                break;
        default:
                assert_not_reached();
        }

        if (type != SERVER_FALLBACK &&
            m->current_server_name &&
            m->current_server_name->type == SERVER_FALLBACK)
                manager_set_server_name(m, NULL);

        log_debug("Added new %s server %s.", server_type_to_string(type), string);

        if (ret)
                *ret = n;

        return 0;
}

ServerName *server_name_free(ServerName *n) {
        if (!n)
                return NULL;

        server_name_flush_addresses(n);

        if (n->manager) {
                if (n->type == SERVER_SYSTEM)
                        LIST_REMOVE(names, n->manager->system_servers, n);
                else if (n->type == SERVER_LINK)
                        LIST_REMOVE(names, n->manager->link_servers, n);
                else if (n->type == SERVER_FALLBACK)
                        LIST_REMOVE(names, n->manager->fallback_servers, n);
                else if (n->type == SERVER_RUNTIME)
                        LIST_REMOVE(names, n->manager->runtime_servers, n);
                else
                        assert_not_reached();

                if (n->manager->current_server_name == n)
                        manager_set_server_name(n->manager, NULL);
        }

        log_debug("Removed server %s.", n->string);

        free(n->string);
        return mfree(n);
}

void server_name_flush_addresses(ServerName *n) {
        assert(n);

        while (n->addresses)
                server_address_free(n->addresses);
}
