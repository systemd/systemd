/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Machine Machine;
typedef enum KillWho KillWho;

#include "list.h"
#include "machined.h"
#include "operation.h"
#include "time-util.h"

typedef enum MachineState {
        MACHINE_OPENING,    /* Machine is being registered */
        MACHINE_RUNNING,    /* Machine is running */
        MACHINE_CLOSING,    /* Machine is terminating */
        _MACHINE_STATE_MAX,
        _MACHINE_STATE_INVALID = -EINVAL,
} MachineState;

typedef enum MachineClass {
        MACHINE_CONTAINER,
        MACHINE_VM,
        MACHINE_HOST,
        _MACHINE_CLASS_MAX,
        _MACHINE_CLASS_INVALID = -EINVAL,
} MachineClass;

enum KillWho {
        KILL_LEADER,
        KILL_ALL,
        _KILL_WHO_MAX,
        _KILL_WHO_INVALID = -EINVAL,
};

struct Machine {
        Manager *manager;

        char *name;
        sd_id128_t id;

        MachineClass class;

        char *state_file;
        char *service;
        char *root_directory;

        char *unit;
        char *scope_job;

        pid_t leader;

        dual_timestamp timestamp;

        bool in_gc_queue:1;
        bool started:1;
        bool stopping:1;
        bool referenced:1;

        sd_bus_message *create_message;

        int *netif;
        size_t n_netif;

        LIST_HEAD(Operation, operations);

        LIST_FIELDS(Machine, gc_queue);
};

Machine* machine_new(Manager *manager, MachineClass class, const char *name);
Machine* machine_free(Machine *m);
bool machine_may_gc(Machine *m, bool drop_not_started);
void machine_add_to_gc_queue(Machine *m);
int machine_start(Machine *m, sd_bus_message *properties, sd_bus_error *error);
int machine_stop(Machine *m);
int machine_finalize(Machine *m);
int machine_save(Machine *m);
int machine_load(Machine *m);
int machine_kill(Machine *m, KillWho who, int signo);

void machine_release_unit(Machine *m);

MachineState machine_get_state(Machine *u);

const char* machine_class_to_string(MachineClass t) _const_;
MachineClass machine_class_from_string(const char *s) _pure_;

const char* machine_state_to_string(MachineState t) _const_;
MachineState machine_state_from_string(const char *s) _pure_;

const char *kill_who_to_string(KillWho k) _const_;
KillWho kill_who_from_string(const char *s) _pure_;

int machine_openpt(Machine *m, int flags, char **ret_slave);
int machine_open_terminal(Machine *m, const char *path, int mode);

int machine_get_uid_shift(Machine *m, uid_t *ret);

int machine_owns_uid(Machine *m, uid_t host_uid, uid_t *ret_internal_uid);
int machine_owns_gid(Machine *m, gid_t host_gid, gid_t *ret_internal_gid);

int machine_translate_uid(Machine *m, uid_t internal_uid, uid_t *ret_host_uid);
int machine_translate_gid(Machine *m, gid_t internal_gid, gid_t *ret_host_gid);
