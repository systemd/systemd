/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2017 Lennart Poettering

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

#include <inttypes.h>
#include <sys/types.h>

#include "sd-id128.h"

typedef struct ClientContext ClientContext;

#include "journald-server.h"

struct ClientContext {
        unsigned n_ref;
        unsigned lru_index;
        usec_t timestamp;
        bool in_lru;

        pid_t pid;
        uid_t uid;
        gid_t gid;

        char *comm;
        char *exe;
        char *cmdline;
        char *capeff;

        uint32_t auditid;
        uid_t loginuid;

        char *cgroup;
        char *session;
        uid_t owner_uid;

        char *unit;
        char *user_unit;

        char *slice;
        char *user_slice;

        sd_id128_t invocation_id;

        char *label;
        size_t label_size;

        int log_level_max;

        struct iovec *extra_fields_iovec;
        size_t extra_fields_n_iovec;
        void *extra_fields_data;
        nsec_t extra_fields_mtime;
};

int client_context_get(
                Server *s,
                pid_t pid,
                const struct ucred *ucred,
                const char *label, size_t label_len,
                const char *unit_id,
                ClientContext **ret);

int client_context_acquire(
                Server *s,
                pid_t pid,
                const struct ucred *ucred,
                const char *label, size_t label_len,
                const char *unit_id,
                ClientContext **ret);

ClientContext* client_context_release(Server *s, ClientContext *c);

void client_context_maybe_refresh(
                Server *s,
                ClientContext *c,
                const struct ucred *ucred,
                const char *label, size_t label_size,
                const char *unit_id,
                usec_t tstamp);

void client_context_acquire_default(Server *s);
void client_context_flush_all(Server *s);

static inline size_t client_context_extra_fields_n_iovec(const ClientContext *c) {
        return c ? c->extra_fields_n_iovec : 0;
}

static inline bool client_context_test_priority(const ClientContext *c, int priority) {
        if (!c)
                return true;

        if (c->log_level_max < 0)
                return true;

        return LOG_PRI(priority) <= c->log_level_max;
}
