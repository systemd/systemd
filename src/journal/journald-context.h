/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <syslog.h>

#include "sd-id128.h"

#include "capability-util.h"
#include "journald-forward.h"

typedef struct ClientContext {
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
        bool log_ratelimit_interval_from_unit;
        bool log_ratelimit_burst_from_unit;

        Set *log_filter_allowed_patterns;
        Set *log_filter_denied_patterns;
} ClientContext;

int client_context_get(
                Manager *m,
                pid_t pid,
                const struct ucred *ucred,
                const char *label, size_t label_len,
                const char *unit_id,
                ClientContext **ret);

int client_context_acquire(
                Manager *m,
                pid_t pid,
                const struct ucred *ucred,
                const char *label, size_t label_len,
                const char *unit_id,
                ClientContext **ret);

ClientContext* client_context_release(Manager *m, ClientContext *c);

void client_context_maybe_refresh(
                Manager *m,
                ClientContext *c,
                const struct ucred *ucred,
                const char *label, size_t label_size,
                const char *unit_id,
                usec_t tstamp);

void manager_refresh_client_contexts_on_reload(Manager *m, usec_t old_interval, unsigned old_burst);
void client_context_acquire_default(Manager *m);
void client_context_flush_all(Manager *m);
void client_context_flush_regular(Manager *m);

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
