/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "sd-id128.h"

#include "capability-util.h"
#include "set.h"
#include "time-util.h"

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
        CapabilityQuintet capability_quintet;

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

        usec_t log_ratelimit_interval;
        unsigned log_ratelimit_burst;

        Set *log_filter_allowed_patterns;
        Set *log_filter_denied_patterns;
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
void client_context_flush_regular(Server *s);

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
