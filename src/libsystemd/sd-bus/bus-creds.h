/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct sd_bus_creds {
        bool allocated;
        unsigned n_ref;

        uint64_t mask;
        uint64_t augmented;

        uid_t uid;
        uid_t euid;
        uid_t suid;
        uid_t fsuid;
        gid_t gid;
        gid_t egid;
        gid_t sgid;
        gid_t fsgid;

        gid_t *supplementary_gids;
        unsigned n_supplementary_gids;

        pid_t ppid;
        pid_t pid;
        pid_t tid;
        int pidfd;

        char *comm;
        char *tid_comm;
        char *exe;

        char *cmdline;
        size_t cmdline_size;
        char **cmdline_array;

        char *cgroup;
        char *session;
        char *unit;
        char *user_unit;
        char *slice;
        char *user_slice;

        char *tty;

        uint32_t *capability;

        uint32_t audit_session_id;
        uid_t audit_login_uid;

        char *label;

        char *unique_name;

        char **well_known_names;
        bool well_known_names_driver:1;
        bool well_known_names_local:1;

        char *cgroup_root;

        char *description, *unescaped_description;
} sd_bus_creds;

#define SD_BUS_CREDS_INIT_FIELDS        \
        .uid = UID_INVALID,             \
        .euid = UID_INVALID,            \
        .suid = UID_INVALID,            \
        .fsuid = UID_INVALID,           \
        .gid = GID_INVALID,             \
        .egid = GID_INVALID,            \
        .sgid = GID_INVALID,            \
        .fsgid = GID_INVALID,           \
        .pidfd = -EBADF,                \
        .audit_login_uid = UID_INVALID

sd_bus_creds* bus_creds_new(void);

void bus_creds_done(sd_bus_creds *c);

int bus_creds_add_more(sd_bus_creds *c, uint64_t mask, PidRef *pidref, pid_t tid);
