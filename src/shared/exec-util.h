/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "time-util.h"

typedef int (*gather_stdout_callback_t) (int fd, void *arg);

enum {
        STDOUT_GENERATE,   /* from generators to helper process */
        STDOUT_COLLECT,    /* from helper process to main process */
        STDOUT_CONSUME,    /* process data in main process */
        _STDOUT_CONSUME_MAX,
};

typedef enum ExecDirFlags {
        EXEC_DIR_PARALLEL             = 1 << 0, /* Execute scripts in parallel, if possible */
        EXEC_DIR_IGNORE_ERRORS        = 1 << 1, /* Ignore non-zero exit status of scripts */
        EXEC_DIR_SET_SYSTEMD_EXEC_PID = 1 << 2, /* Set $SYSTEMD_EXEC_PID environment variable */
        EXEC_DIR_SKIP_REMAINING       = 1 << 3, /* Ignore remaining executions when one exit with 77. */
        EXEC_DIR_WARN_WORLD_WRITABLE  = 1 << 4, /* Warn if world writable files are found */
} ExecDirFlags;

int execute_strv(
                const char *name,
                char * const *paths,
                const char *root,
                usec_t timeout,
                gather_stdout_callback_t const callbacks[_STDOUT_CONSUME_MAX],
                void * const callback_args[_STDOUT_CONSUME_MAX],
                char *argv[],
                char *envp[],
                ExecDirFlags flags);

int execute_directories(
                const char * const *directories,
                usec_t timeout,
                gather_stdout_callback_t const callbacks[_STDOUT_CONSUME_MAX],
                void * const callback_args[_STDOUT_CONSUME_MAX],
                char *argv[],
                char *envp[],
                ExecDirFlags flags);

extern const gather_stdout_callback_t gather_environment[_STDOUT_CONSUME_MAX];

typedef enum ExecCommandFlags {
        EXEC_COMMAND_IGNORE_FAILURE   = 1 << 0,
        EXEC_COMMAND_FULLY_PRIVILEGED = 1 << 1,
        EXEC_COMMAND_NO_SETUID        = 1 << 2,
        EXEC_COMMAND_NO_ENV_EXPAND    = 1 << 3,
        _EXEC_COMMAND_FLAGS_INVALID   = -EINVAL,
        _EXEC_COMMAND_FLAGS_ALL       = (1 << 4) -1,
} ExecCommandFlags;

int exec_command_flags_from_strv(char * const *ex_opts, ExecCommandFlags *ret);
int exec_command_flags_to_strv(ExecCommandFlags flags, char ***ret);

const char* exec_command_flags_to_string(ExecCommandFlags i);
ExecCommandFlags exec_command_flags_from_string(const char *s);

int fexecve_or_execve(int executable_fd, const char *executable, char *const argv[], char *const envp[]);

int shall_fork_agent(void);
int _fork_agent(const char *name, const int except[], size_t n_except, pid_t *ret_pid, const char *path, ...) _sentinel_;
#define fork_agent(name, ...) _fork_agent(name, __VA_ARGS__, NULL)
