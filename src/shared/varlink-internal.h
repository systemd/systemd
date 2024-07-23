/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

#include "fdset.h"
#include "varlink.h"

typedef struct VarlinkServerSocket VarlinkServerSocket;

struct VarlinkServerSocket {
        VarlinkServer *server;

        int fd;
        char *address;

        sd_event_source *event_source;

        LIST_FIELDS(VarlinkServerSocket, sockets);
};

struct VarlinkServer {
        unsigned n_ref;
        VarlinkServerFlags flags;

        LIST_HEAD(VarlinkServerSocket, sockets);

        Hashmap *methods;              /* Fully qualified symbol name of a method → VarlinkMethod */
        Hashmap *interfaces;           /* Fully qualified interface name → VarlinkInterface* */
        Hashmap *symbols;              /* Fully qualified symbol name of method/error → VarlinkSymbol* */
        VarlinkConnect connect_callback;
        VarlinkDisconnect disconnect_callback;

        sd_event *event;
        int64_t event_priority;

        unsigned n_connections;
        Hashmap *by_uid;               /* UID_TO_PTR(uid) → UINT_TO_PTR(n_connections) */

        void *userdata;
        char *description;

        unsigned connections_max;
        unsigned connections_per_uid_max;

        bool exit_on_idle;
};

int varlink_server_serialize(VarlinkServer *s, FILE *f, FDSet *fds);
int varlink_server_deserialize_one(VarlinkServer *s, const char *value, FDSet *fds);
