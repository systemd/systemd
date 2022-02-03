/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct SocketGraveyard SocketGraveyard;

#include "resolved-manager.h"

struct SocketGraveyard {
        Manager *manager;
        usec_t deadline;
        sd_event_source *io_event_source;
        LIST_FIELDS(SocketGraveyard, graveyard);
};

void manager_socket_graveyard_process(Manager *m);
void manager_socket_graveyard_clear(Manager *m);

int manager_add_socket_to_graveyard(Manager *m, int fd);
