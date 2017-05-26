/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Susant Sahani

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

#pragma once

#include "sd-event.h"
#include "sd-network.h"
#include "socket-util.h"
#include "sd-journal.h"

typedef struct Manager Manager;

struct Manager {
        sd_event *event;
        sd_event_source *event_journal_input;
        uint64_t timeout;

        sd_event_source *sigint_event, *sigterm_event;

        /* network */
        sd_event_source *network_event_source;
        sd_network_monitor *network_monitor;

        int socket;

        /* Multicast UDP address */
        SocketAddress address;

        /* journal  */
        int journal_watch_fd;
        sd_journal *journal;

        char *state_file;

        char *last_cursor, *current_cursor;
};

int manager_new(Manager **ret, const char *state_file, const char *cursor);
void manager_free(Manager *m);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

int manager_connect(Manager *m);
void manager_disconnect(Manager *m);

void manager_close_network_socket(Manager *m);
int manager_open_network_socket(Manager *m);

int manager_push_to_network(Manager *m, int severity, int facility,
                            const char *identifier, const char *message,
                            const char *hostname, const char *pid,
                            const struct timeval *tv);
