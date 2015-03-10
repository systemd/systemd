/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

#include "socket-util.h"
#include "list.h"

typedef struct ServerAddress ServerAddress;
typedef struct ServerName ServerName;

typedef enum ServerType {
        SERVER_SYSTEM,
        SERVER_FALLBACK,
        SERVER_LINK,
} ServerType;

#include "timesyncd-manager.h"

struct ServerAddress {
        ServerName *name;

        union sockaddr_union sockaddr;
        socklen_t socklen;

        LIST_FIELDS(ServerAddress, addresses);
};

struct ServerName {
        Manager *manager;

        ServerType type;
        char *string;

        bool marked:1;

        LIST_HEAD(ServerAddress, addresses);
        LIST_FIELDS(ServerName, names);
};

int server_address_new(ServerName *n, ServerAddress **ret, const union sockaddr_union *sockaddr, socklen_t socklen);
ServerAddress* server_address_free(ServerAddress *a);
static inline int server_address_pretty(ServerAddress *a, char **pretty) {
        return sockaddr_pretty(&a->sockaddr.sa, a->socklen, true, true, pretty);
}

int server_name_new(Manager *m, ServerName **ret, ServerType type,const char *string);
ServerName *server_name_free(ServerName *n);
void server_name_flush_addresses(ServerName *n);
