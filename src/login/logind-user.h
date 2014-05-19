/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

typedef struct User User;

#include "list.h"
#include "util.h"
#include "logind.h"
#include "logind-session.h"

typedef enum UserState {
        USER_OFFLINE,    /* Not logged in at all */
        USER_OPENING,    /* Is logging in */
        USER_LINGERING,  /* Lingering has been enabled by the admin for this user */
        USER_ONLINE,     /* User logged in */
        USER_ACTIVE,     /* User logged in and has a session in the fg */
        USER_CLOSING,    /* User logged out, but processes still remain and lingering is not enabled */
        _USER_STATE_MAX,
        _USER_STATE_INVALID = -1
} UserState;

struct User {
        Manager *manager;

        uid_t uid;
        gid_t gid;
        char *name;

        char *state_file;
        char *runtime_path;

        char *service;
        char *slice;

        char *service_job;
        char *slice_job;

        Session *display;

        dual_timestamp timestamp;

        bool in_gc_queue:1;
        bool started:1;
        bool stopping:1;

        LIST_HEAD(Session, sessions);
        LIST_FIELDS(User, gc_queue);
};

User* user_new(Manager *m, uid_t uid, gid_t gid, const char *name);
void user_free(User *u);
bool user_check_gc(User *u, bool drop_not_started);
void user_add_to_gc_queue(User *u);
int user_start(User *u);
int user_stop(User *u, bool force);
int user_finalize(User *u);
UserState user_get_state(User *u);
int user_get_idle_hint(User *u, dual_timestamp *t);
int user_save(User *u);
int user_load(User *u);
int user_kill(User *u, int signo);
int user_check_linger_file(User *u);
void user_elect_display(User *u);

extern const sd_bus_vtable user_vtable[];
int user_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error);
int user_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error);
char *user_bus_path(User *s);

int user_send_signal(User *u, bool new_user);
int user_send_changed(User *u, const char *properties, ...) _sentinel_;

const char* user_state_to_string(UserState s) _const_;
UserState user_state_from_string(const char *s) _pure_;
