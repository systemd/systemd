/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

typedef struct ExecStatus ExecStatus;
typedef struct ExecCommand ExecCommand;
typedef struct ExecContext ExecContext;
typedef struct ExecRuntime ExecRuntime;
typedef struct ExecParameters ExecParameters;

#include <sys/capability.h>
#include <stdbool.h>
#include <stdio.h>
#include <sched.h>

#include "list.h"
#include "fdset.h"
#include "missing.h"
#include "namespace.h"
#include "bus-endpoint.h"

typedef enum ExecUtmpMode {
        EXEC_UTMP_INIT,
        EXEC_UTMP_LOGIN,
        EXEC_UTMP_USER,
        _EXEC_UTMP_MODE_MAX,
        _EXEC_UTMP_MODE_INVALID = -1
} ExecUtmpMode;

typedef enum ExecInput {
        EXEC_INPUT_NULL,
        EXEC_INPUT_TTY,
        EXEC_INPUT_TTY_FORCE,
        EXEC_INPUT_TTY_FAIL,
        EXEC_INPUT_SOCKET,
        _EXEC_INPUT_MAX,
        _EXEC_INPUT_INVALID = -1
} ExecInput;

typedef enum ExecOutput {
        EXEC_OUTPUT_INHERIT,
        EXEC_OUTPUT_NULL,
        EXEC_OUTPUT_TTY,
        EXEC_OUTPUT_SYSLOG,
        EXEC_OUTPUT_SYSLOG_AND_CONSOLE,
        EXEC_OUTPUT_KMSG,
        EXEC_OUTPUT_KMSG_AND_CONSOLE,
        EXEC_OUTPUT_JOURNAL,
        EXEC_OUTPUT_JOURNAL_AND_CONSOLE,
        EXEC_OUTPUT_SOCKET,
        _EXEC_OUTPUT_MAX,
        _EXEC_OUTPUT_INVALID = -1
} ExecOutput;

struct ExecStatus {
        dual_timestamp start_timestamp;
        dual_timestamp exit_timestamp;
        pid_t pid;
        int code;     /* as in siginfo_t::si_code */
        int status;   /* as in sigingo_t::si_status */
};

struct ExecCommand {
        char *path;
        char **argv;
        ExecStatus exec_status;
        LIST_FIELDS(ExecCommand, command); /* useful for chaining commands */
        bool ignore;
};

struct ExecRuntime {
        int n_ref;

        char *tmp_dir;
        char *var_tmp_dir;

        int netns_storage_socket[2];
};

struct ExecContext {
        char **environment;
        char **environment_files;

        struct rlimit *rlimit[_RLIMIT_MAX];
        char *working_directory, *root_directory;
        bool working_directory_missing_ok;

        mode_t umask;
        int oom_score_adjust;
        int nice;
        int ioprio;
        int cpu_sched_policy;
        int cpu_sched_priority;

        cpu_set_t *cpuset;
        unsigned cpuset_ncpus;

        ExecInput std_input;
        ExecOutput std_output;
        ExecOutput std_error;

        nsec_t timer_slack_nsec;

        char *tty_path;

        bool tty_reset;
        bool tty_vhangup;
        bool tty_vt_disallocate;

        bool ignore_sigpipe;

        /* Since resolving these names might might involve socket
         * connections and we don't want to deadlock ourselves these
         * names are resolved on execution only and in the child
         * process. */
        char *user;
        char *group;
        char **supplementary_groups;

        char *pam_name;

        char *utmp_id;
        ExecUtmpMode utmp_mode;

        bool selinux_context_ignore;
        char *selinux_context;

        bool apparmor_profile_ignore;
        char *apparmor_profile;

        bool smack_process_label_ignore;
        char *smack_process_label;

        char **read_write_dirs, **read_only_dirs, **inaccessible_dirs;
        unsigned long mount_flags;

        uint64_t capability_bounding_set_drop;

        cap_t capabilities;
        int secure_bits;

        int syslog_priority;
        char *syslog_identifier;
        bool syslog_level_prefix;

        bool cpu_sched_reset_on_fork;
        bool non_blocking;
        bool private_tmp;
        bool private_network;
        bool private_devices;
        ProtectSystem protect_system;
        ProtectHome protect_home;

        bool no_new_privileges;

        /* This is not exposed to the user but available
         * internally. We need it to make sure that whenever we spawn
         * /usr/bin/mount it is run in the same process group as us so
         * that the autofs logic detects that it belongs to us and we
         * don't enter a trigger loop. */
        bool same_pgrp;

        unsigned long personality;

        Set *syscall_filter;
        Set *syscall_archs;
        int syscall_errno;
        bool syscall_whitelist:1;

        Set *address_families;
        bool address_families_whitelist:1;

        char **runtime_directory;
        mode_t runtime_directory_mode;

        bool oom_score_adjust_set:1;
        bool nice_set:1;
        bool ioprio_set:1;
        bool cpu_sched_set:1;
        bool no_new_privileges_set:1;

        /* custom dbus enpoint */
        BusEndpoint *bus_endpoint;
};

#include "cgroup.h"
#include "cgroup-util.h"

struct ExecParameters {
        char **argv;
        int *fds; unsigned n_fds;
        char **environment;
        bool apply_permissions;
        bool apply_chroot;
        bool apply_tty_stdin;
        bool confirm_spawn;
        bool selinux_context_net;
        CGroupControllerMask cgroup_supported;
        const char *cgroup_path;
        bool cgroup_delegate;
        const char *runtime_prefix;
        usec_t watchdog_usec;
        int *idle_pipe;
        char *bus_endpoint_path;
        int bus_endpoint_fd;
};

int exec_spawn(Unit *unit,
               ExecCommand *command,
               const ExecContext *context,
               const ExecParameters *exec_params,
               ExecRuntime *runtime,
               pid_t *ret);

void exec_command_done(ExecCommand *c);
void exec_command_done_array(ExecCommand *c, unsigned n);

ExecCommand* exec_command_free_list(ExecCommand *c);
void exec_command_free_array(ExecCommand **c, unsigned n);

char *exec_command_line(char **argv);

void exec_command_dump(ExecCommand *c, FILE *f, const char *prefix);
void exec_command_dump_list(ExecCommand *c, FILE *f, const char *prefix);
void exec_command_append_list(ExecCommand **l, ExecCommand *e);
int exec_command_set(ExecCommand *c, const char *path, ...);
int exec_command_append(ExecCommand *c, const char *path, ...);

void exec_context_init(ExecContext *c);
void exec_context_done(ExecContext *c);
void exec_context_dump(ExecContext *c, FILE* f, const char *prefix);

int exec_context_destroy_runtime_directory(ExecContext *c, const char *runtime_root);

int exec_context_load_environment(Unit *unit, const ExecContext *c, char ***l);

bool exec_context_may_touch_console(ExecContext *c);
bool exec_context_maintains_privileges(ExecContext *c);

void exec_status_start(ExecStatus *s, pid_t pid);
void exec_status_exit(ExecStatus *s, ExecContext *context, pid_t pid, int code, int status);
void exec_status_dump(ExecStatus *s, FILE *f, const char *prefix);

int exec_runtime_make(ExecRuntime **rt, ExecContext *c, const char *id);
ExecRuntime *exec_runtime_ref(ExecRuntime *r);
ExecRuntime *exec_runtime_unref(ExecRuntime *r);

int exec_runtime_serialize(Unit *unit, ExecRuntime *rt, FILE *f, FDSet *fds);
int exec_runtime_deserialize_item(Unit *unit, ExecRuntime **rt, const char *key, const char *value, FDSet *fds);

void exec_runtime_destroy(ExecRuntime *rt);

const char* exec_output_to_string(ExecOutput i) _const_;
ExecOutput exec_output_from_string(const char *s) _pure_;

const char* exec_input_to_string(ExecInput i) _const_;
ExecInput exec_input_from_string(const char *s) _pure_;

const char* exec_utmp_mode_to_string(ExecUtmpMode i) _const_;
ExecUtmpMode exec_utmp_mode_from_string(const char *s) _pure_;
