/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foologindsessionhfoo
#define foologindsessionhfoo

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

typedef struct Session Session;

#include "list.h"
#include "util.h"
#include "logind.h"
#include "logind-seat.h"
#include "logind-user.h"

typedef enum SessionType {
        SESSION_TTY,
        SESSION_X11,
        _SESSION_TYPE_MAX,
        _SESSION_TYPE_INVALID = -1
} SessionType;

struct Session {
        Manager *manager;

        char *id;
        SessionType type;

        char *state_file;

        User *user;

        dual_timestamp timestamp;

        char *tty;
        char *display;

        bool remote;
        char *remote_user;
        char *remote_host;

        int vtnr;
        Seat *seat;

        pid_t leader;
        uint32_t audit_id;

        int pipe_fd;

        char *cgroup_path;
        char **controllers, **reset_controllers;

        bool idle_hint;
        dual_timestamp idle_hint_timestamp;

        bool kill_processes;
        bool in_gc_queue:1;

        LIST_FIELDS(Session, sessions_by_user);
        LIST_FIELDS(Session, sessions_by_seat);

        LIST_FIELDS(Session, gc_queue);
};

Session *session_new(Manager *m, User *u, const char *id);
void session_free(Session *s);
int session_check_gc(Session *s);
void session_add_to_gc_queue(Session *s);
int session_activate(Session *s);
bool session_is_active(Session *s);
int session_get_idle_hint(Session *s, dual_timestamp *t);
void session_set_idle_hint(Session *s, bool b);
int session_start(Session *s);
int session_stop(Session *s);
int session_save(Session *s);
int session_load(Session *s);

char *session_bus_path(Session *s);

extern const DBusObjectPathVTable bus_session_vtable;

const char* session_type_to_string(SessionType t);
SessionType session_type_from_string(const char *s);

#endif
