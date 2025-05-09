/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "list.h"

typedef struct Manager Manager;
typedef struct SocketGraveyard SocketGraveyard;

struct SocketGraveyard {
        Manager *manager;
        usec_t deadline;
        sd_event_source *io_event_source;
        LIST_FIELDS(SocketGraveyard, graveyard);
};

void manager_socket_graveyard_process(Manager *m);
void manager_socket_graveyard_clear(Manager *m);

int manager_add_socket_to_graveyard(Manager *m, int fd);
