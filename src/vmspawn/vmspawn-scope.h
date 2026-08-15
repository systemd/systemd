/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct SocketServicePair {
        char **exec_start_pre;
        char **exec_start;
        char **exec_stop_post;
        char *unit_name_prefix;
        char *listen_address;
        int socket_type;
} SocketServicePair;

void socket_service_pair_done(SocketServicePair *p);

int allocate_scope(
                sd_bus *bus,
                const char *machine_name,
                const PidRef *pid,
                sd_event_source **auxiliary,
                size_t n_auxiliary,
                const char *scope,
                const char *slice,
                char **properties,
                bool allow_pidfd);

int terminate_scope(sd_bus *bus, const char *scope);
