/*-*- Mode: C; c-basic-offset: 8 -*-*/

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
        EXEC_OUTPUT_KERNEL,
        EXEC_OUTPUT_SOCKET,
        _EXEC_OUTPUT_MAX,
        _EXEC_OUTPUT_INVALID = -1
} ExecOutput;

struct ExecStatus {
        usec_t start_timestamp;
        usec_t exit_timestamp;
        pid_t pid;
        int code;     /* as in siginfo_t::si_code */
        int status;   /* as in sigingo_t::si_status */
};

struct ExecCommand {
        char *path;
        char **argv;
        ExecStatus exec_status;
        LIST_FIELDS(ExecCommand, command); /* useful for chaining commands */
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

        cpu_set_t cpu_affinity;
        unsigned long timer_slack_ns;

        ExecInput std_input;
        ExecOutput std_output;
        ExecOutput std_error;

        int syslog_priority;
        char *syslog_identifier;
        bool syslog_no_prefix;

        char *tty_path;

        /* Since resolving these names might might involve socket
         * connections and we don't want to deadlock ourselves these
         * names are resolved on execution only and in the child
         * process. */
        char *user;
        char *group;
        char **supplementary_groups;

        char **read_write_dirs, **read_only_dirs, **inaccessible_dirs;
        unsigned long mount_flags;

        uint64_t capability_bounding_set_drop;

        cap_t capabilities;
        int secure_bits;

        bool cpu_sched_reset_on_fork;
        bool non_blocking;
        bool private_tmp;

        bool oom_adjust_set:1;
        bool nice_set:1;
        bool ioprio_set:1;
        bool cpu_sched_set:1;
        bool cpu_affinity_set:1;
        bool timer_slack_ns_set:1;

        /* This is not exposed to the user but available
         * internally. We need it to make sure that whenever we spawn
         * /bin/mount it is run in the same process group as us so
         * that the autofs logic detects that it belongs to us and we
         * don't enter a trigger loop. */
        bool no_setsid:1;
};

typedef enum ExitStatus {
        /* EXIT_SUCCESS defined by libc */
        /* EXIT_FAILURE defined by libc */
        EXIT_INVALIDARGUMENT = 2,
        EXIT_NOTIMPLEMENTED = 3,
        EXIT_NOPERMISSION = 4,
        EXIT_NOTINSTALLED = 5,
        EXIT_NOTCONFIGURED = 6,
        EXIT_NOTRUNNING = 7,

        /* The LSB suggests that error codes >= 200 are "reserved". We
         * use them here under the assumption that they hence are
         * unused by init scripts.
         *
         * http://refspecs.freestandards.org/LSB_3.1.0/LSB-Core-generic/LSB-Core-generic/iniscrptact.html */

        EXIT_CHDIR = 200,
        EXIT_NICE,
        EXIT_FDS,
        EXIT_EXEC,
        EXIT_MEMORY,
        EXIT_LIMITS,
        EXIT_OOM_ADJUST,
        EXIT_SIGNAL_MASK,
        EXIT_STDIN,
        EXIT_STDOUT,
        EXIT_CHROOT,   /* 210 */
        EXIT_IOPRIO,
        EXIT_TIMERSLACK,
        EXIT_SECUREBITS,
        EXIT_SETSCHEDULER,
        EXIT_CPUAFFINITY,
        EXIT_GROUP,
        EXIT_USER,
        EXIT_CAPABILITIES,
        EXIT_CGROUP,
        EXIT_SETSID,   /* 220 */
        EXIT_CONFIRM,
        EXIT_STDERR

} ExitStatus;

int exec_spawn(ExecCommand *command,
               char **argv,
               const ExecContext *context,
               int fds[], unsigned n_fds,
               char **environment,
               bool apply_permissions,
               bool apply_chroot,
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

void exec_status_fill(ExecStatus *s, pid_t pid, int code, int status);
void exec_status_dump(ExecStatus *s, FILE *f, const char *prefix);

const char* exec_output_to_string(ExecOutput i);
int exec_output_from_string(const char *s);

const char* exec_input_to_string(ExecInput i);
int exec_input_from_string(const char *s);

const char* exit_status_to_string(ExitStatus status);

#endif
