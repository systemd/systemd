/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef fooexecutehfoo
#define fooexecutehfoo

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

typedef struct ExecStatus ExecStatus;
typedef struct ExecCommand ExecCommand;
typedef struct ExecContext ExecContext;

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/capability.h>
#include <stdbool.h>
#include <stdio.h>
#include <sched.h>

struct CGroupBonding;

#include "list.h"
#include "util.h"

/* Abstract namespace! */
#define LOGGER_SOCKET "/org/freedesktop/systemd1/logger"

/* This doesn't really belong here, but I couldn't find a better place to put this. */
#define SIGNALS_CRASH_HANDLER SIGSEGV,SIGILL,SIGFPE,SIGBUS,SIGQUIT,SIGABRT
#define SIGNALS_IGNORE SIGKILL,SIGPIPE

typedef enum KillMode {
        KILL_CONTROL_GROUP = 0,
        KILL_PROCESS_GROUP,
        KILL_PROCESS,
        KILL_NONE,
        _KILL_MODE_MAX,
        _KILL_MODE_INVALID = -1
} KillMode;

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
        EXEC_OUTPUT_KMSG,
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

struct ExecContext {
        char **environment;
        struct rlimit *rlimit[RLIMIT_NLIMITS];
        char *working_directory, *root_directory;

        mode_t umask;
        int oom_adjust;
        int nice;
        int ioprio;
        int cpu_sched_policy;
        int cpu_sched_priority;

        cpu_set_t *cpuset;
        unsigned cpuset_ncpus;

        ExecInput std_input;
        ExecOutput std_output;
        ExecOutput std_error;

        unsigned long timer_slack_nsec;

        char *tcpwrap_name;

        char *tty_path;

        /* Since resolving these names might might involve socket
         * connections and we don't want to deadlock ourselves these
         * names are resolved on execution only and in the child
         * process. */
        char *user;
        char *group;
        char **supplementary_groups;

        char *pam_name;

        char **read_write_dirs, **read_only_dirs, **inaccessible_dirs;
        unsigned long mount_flags;

        uint64_t capability_bounding_set_drop;

        /* Not relevant for spawning processes, just for killing */
        KillMode kill_mode;
        int kill_signal;

        cap_t capabilities;
        int secure_bits;

        int syslog_priority;
        char *syslog_identifier;
        bool syslog_level_prefix;

        bool cpu_sched_reset_on_fork;
        bool non_blocking;
        bool private_tmp;

        /* This is not exposed to the user but available
         * internally. We need it to make sure that whenever we spawn
         * /bin/mount it is run in the same process group as us so
         * that the autofs logic detects that it belongs to us and we
         * don't enter a trigger loop. */
        bool same_pgrp;

        bool oom_adjust_set:1;
        bool nice_set:1;
        bool ioprio_set:1;
        bool cpu_sched_set:1;
        bool timer_slack_nsec_set:1;
};

int exec_spawn(ExecCommand *command,
               char **argv,
               const ExecContext *context,
               int fds[], unsigned n_fds,
               char **environment,
               bool apply_permissions,
               bool apply_chroot,
               bool apply_tty_stdin,
               bool confirm_spawn,
               struct CGroupBonding *cgroup_bondings,
               pid_t *ret);

void exec_command_done(ExecCommand *c);
void exec_command_done_array(ExecCommand *c, unsigned n);

void exec_command_free_list(ExecCommand *c);
void exec_command_free_array(ExecCommand **c, unsigned n);

char *exec_command_line(char **argv);

void exec_command_dump(ExecCommand *c, FILE *f, const char *prefix);
void exec_command_dump_list(ExecCommand *c, FILE *f, const char *prefix);
void exec_command_append_list(ExecCommand **l, ExecCommand *e);
int exec_command_set(ExecCommand *c, const char *path, ...);

void exec_context_init(ExecContext *c);
void exec_context_done(ExecContext *c);
void exec_context_dump(ExecContext *c, FILE* f, const char *prefix);

void exec_status_start(ExecStatus *s, pid_t pid);
void exec_status_exit(ExecStatus *s, pid_t pid, int code, int status);
void exec_status_dump(ExecStatus *s, FILE *f, const char *prefix);

const char* exec_output_to_string(ExecOutput i);
int exec_output_from_string(const char *s);

const char* exec_input_to_string(ExecInput i);
int exec_input_from_string(const char *s);

#endif
