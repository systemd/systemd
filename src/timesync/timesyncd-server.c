/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Kay Sievers, Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "timesyncd-server.h"

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

        a = new0(ServerAddress, 1);
        if (!a)
                return -ENOMEM;

        memcpy(&a->sockaddr, sockaddr, socklen);
        a->socklen = socklen;

        LIST_FIND_TAIL(addresses, n->addresses, tail);
        LIST_INSERT_AFTER(addresses, n->addresses, tail, a);
        a->name = n;

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

        free(a);
        return NULL;
}

int server_name_new(
                Manager *m,
                ServerName **ret,
                ServerType type,
                const char *string) {

        ServerName *n, *tail;

        assert(m);
        assert(string);

        n = new0(ServerName, 1);
        if (!n)
                return -ENOMEM;

        n->type = type;
        n->string = strdup(string);
        if (!n->string) {
                free(n);
                return -ENOMEM;
        }

        if (type == SERVER_SYSTEM) {
                LIST_FIND_TAIL(names, m->system_servers, tail);
                LIST_INSERT_AFTER(names, m->system_servers, tail, n);
        } else if (type == SERVER_LINK) {
                LIST_FIND_TAIL(names, m->link_servers, tail);
                LIST_INSERT_AFTER(names, m->link_servers, tail, n);
        } else if (type == SERVER_FALLBACK) {
                LIST_FIND_TAIL(names, m->fallback_servers, tail);
                LIST_INSERT_AFTER(names, m->fallback_servers, tail, n);
        } else
                assert_not_reached("Unknown server type");

        n->manager = m;

        if (type != SERVER_FALLBACK &&
            m->current_server_name &&
            m->current_server_name->type == SERVER_FALLBACK)
                manager_set_server_name(m, NULL);

        log_debug("Added new server %s.", string);

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
                else
                        assert_not_reached("Unknown server type");

                if (n->manager->current_server_name == n)
                        manager_set_server_name(n->manager, NULL);
        }

        log_debug("Removed server %s.", n->string);

        free(n->string);
        free(n);

        return NULL;
}

void server_name_flush_addresses(ServerName *n) {
        assert(n);

        while (n->addresses)
                server_address_free(n->addresses);
}
