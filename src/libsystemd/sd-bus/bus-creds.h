/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include <stdbool.h>

#include "sd-bus.h"

struct sd_bus_creds {
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
};

sd_bus_creds* bus_creds_new(void);

void bus_creds_done(sd_bus_creds *c);

int bus_creds_add_more(sd_bus_creds *c, uint64_t mask, pid_t pid, pid_t tid);

int bus_creds_extend_by_pid(sd_bus_creds *c, uint64_t mask, sd_bus_creds **ret);
