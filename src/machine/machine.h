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

typedef struct Machine Machine;
typedef enum KillWho KillWho;

#include "list.h"
#include "util.h"
#include "machined.h"

typedef enum MachineState {
        MACHINE_OPENING,    /* Machine is being registered */
        MACHINE_RUNNING,    /* Machine is running */
        MACHINE_CLOSING,    /* Machine is terminating */
        _MACHINE_STATE_MAX,
        _MACHINE_STATE_INVALID = -1
} MachineState;

typedef enum MachineClass {
        MACHINE_CONTAINER,
        MACHINE_VM,
        _MACHINE_CLASS_MAX,
        _MACHINE_CLASS_INVALID = -1
} MachineClass;

enum KillWho {
        KILL_LEADER,
        KILL_ALL,
        _KILL_WHO_MAX,
        _KILL_WHO_INVALID = -1
};

struct Machine {
        Manager *manager;

        char *name;
        sd_id128_t id;

        MachineState state;
        MachineClass class;

        char *state_file;
        char *service;
        char *root_directory;

        char *scope;
        char *scope_job;

        pid_t leader;

        dual_timestamp timestamp;

        bool in_gc_queue:1;
        bool started:1;

        DBusMessage *create_message;

        LIST_FIELDS(Machine, gc_queue);
};

Machine* machine_new(Manager *manager, const char *name);
void machine_free(Machine *m);
int machine_check_gc(Machine *m, bool drop_not_started);
void machine_add_to_gc_queue(Machine *m);
int machine_start(Machine *m, DBusMessageIter *iter);
int machine_stop(Machine *m);
int machine_save(Machine *m);
int machine_load(Machine *m);
int machine_kill(Machine *m, KillWho who, int signo);

char *machine_bus_path(Machine *s);

MachineState machine_get_state(Machine *u);

extern const DBusObjectPathVTable bus_machine_vtable;

int machine_send_signal(Machine *m, bool new_machine);
int machine_send_changed(Machine *m, const char *properties);

int machine_send_create_reply(Machine *m, DBusError *error);

const char* machine_class_to_string(MachineClass t) _const_;
MachineClass machine_class_from_string(const char *s) _pure_;

const char* machine_state_to_string(MachineState t) _const_;
MachineState machine_state_from_string(const char *s) _pure_;

const char *kill_who_to_string(KillWho k) _const_;
KillWho kill_who_from_string(const char *s) _pure_;
