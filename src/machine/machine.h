/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Machine Machine;
typedef enum KillWhom KillWhom;

#include "copy.h"
#include "list.h"
#include "machined.h"
#include "operation.h"
#include "pidref.h"
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

enum KillWhom {
        KILL_LEADER,
        KILL_ALL,
        _KILL_WHOM_MAX,
        _KILL_WHOM_INVALID = -EINVAL,
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

        PidRef leader;
        sd_event_source *leader_pidfd_event_source;

        dual_timestamp timestamp;

        bool in_gc_queue:1;
        bool started:1;
        bool stopping:1;
        bool referenced:1;
        bool allocate_unit;

        sd_bus_message *create_message;

        int *netif;
        size_t n_netif;

        unsigned vsock_cid;
        char *ssh_address;
        char *ssh_private_key_path;

        LIST_HEAD(Operation, operations);

        LIST_FIELDS(Machine, gc_queue);
};

int machine_new(MachineClass class, const char *name, Machine **ret);
int machine_link(Manager *manager, Machine *machine);
Machine* machine_free(Machine *m);
bool machine_may_gc(Machine *m, bool drop_not_started);
void machine_add_to_gc_queue(Machine *m);
int machine_start(Machine *m, sd_bus_message *properties, sd_bus_error *error);
int machine_stop(Machine *m);
int machine_finalize(Machine *m);
int machine_save(Machine *m);
int machine_load(Machine *m);
int machine_kill(Machine *m, KillWhom whom, int signo);

DEFINE_TRIVIAL_CLEANUP_FUNC(Machine*, machine_free);

void machine_release_unit(Machine *m);

MachineState machine_get_state(Machine *u);

const char* machine_class_to_string(MachineClass t) _const_;
MachineClass machine_class_from_string(const char *s) _pure_;

const char* machine_state_to_string(MachineState t) _const_;
MachineState machine_state_from_string(const char *s) _pure_;

const char* kill_whom_to_string(KillWhom k) _const_;
KillWhom kill_whom_from_string(const char *s) _pure_;

int machine_openpt(Machine *m, int flags, char **ret_peer);
int machine_start_getty(Machine *m, const char *ptmx_name, sd_bus_error *error);
int machine_start_shell(Machine *m, int ptmx_fd, const char *ptmx_name, const char *user, const char *path, char **args, char **env, sd_bus_error *error);
#define machine_default_shell_path() ("/bin/sh")
char** machine_default_shell_args(const char *user);

int machine_copy_from_to(
                Manager *manager,
                Machine *machine,
                const char *host_path,
                const char *container_path,
                bool copy_from_container,
                CopyFlags copy_flags,
                Operation **ret);

int machine_get_uid_shift(Machine *m, uid_t *ret);

int machine_owns_uid(Machine *m, uid_t host_uid, uid_t *ret_internal_uid);
int machine_owns_gid(Machine *m, gid_t host_gid, gid_t *ret_internal_gid);

int machine_translate_uid(Machine *m, uid_t internal_uid, uid_t *ret_host_uid);
int machine_translate_gid(Machine *m, gid_t internal_gid, gid_t *ret_host_gid);

int machine_open_root_directory(Machine *machine);

typedef enum AcquireMetadata {
        ACQUIRE_METADATA_NO,
        ACQUIRE_METADATA_YES,
        ACQUIRE_METADATA_GRACEFUL,
        _ACQUIRE_METADATA_MAX,
        _ACQUIRE_METADATA_INVALID = -EINVAL,
} AcquireMetadata;

AcquireMetadata acquire_metadata_from_string(const char *s) _pure_;
const char* acquire_metadata_to_string(AcquireMetadata am) _const_;
inline static bool should_acquire_metadata(AcquireMetadata am) {
        return am == ACQUIRE_METADATA_YES || am == ACQUIRE_METADATA_GRACEFUL;
}
