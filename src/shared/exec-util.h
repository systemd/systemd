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

typedef enum {
        EXEC_DIR_NONE                 = 0,      /* No execdir flags */
        EXEC_DIR_PARALLEL             = 1 << 0, /* Execute scripts in parallel, if possible */
        EXEC_DIR_IGNORE_ERRORS        = 1 << 1, /* Ignore non-zero exit status of scripts */
        EXEC_DIR_SET_SYSTEMD_EXEC_PID = 1 << 2, /* Set $SYSTEMD_EXEC_PID environment variable */
} ExecDirFlags;

typedef enum ExecCommandFlags {
        EXEC_COMMAND_IGNORE_FAILURE   = 1 << 0,
        EXEC_COMMAND_FULLY_PRIVILEGED = 1 << 1,
        EXEC_COMMAND_NO_SETUID        = 1 << 2,
        EXEC_COMMAND_AMBIENT_MAGIC    = 1 << 3,
        EXEC_COMMAND_NO_ENV_EXPAND    = 1 << 4,
        _EXEC_COMMAND_FLAGS_INVALID   = -EINVAL,
} ExecCommandFlags;

int execute_directories(
                const char* const* directories,
                usec_t timeout,
                gather_stdout_callback_t const callbacks[_STDOUT_CONSUME_MAX],
                void* const callback_args[_STDOUT_CONSUME_MAX],
                char *argv[],
                char *envp[],
                ExecDirFlags flags);

int exec_command_flags_from_strv(char **ex_opts, ExecCommandFlags *flags);
int exec_command_flags_to_strv(ExecCommandFlags flags, char ***ex_opts);

extern const gather_stdout_callback_t gather_environment[_STDOUT_CONSUME_MAX];

const char* exec_command_flags_to_string(ExecCommandFlags i);
ExecCommandFlags exec_command_flags_from_string(const char *s);

int fexecve_or_execve(int executable_fd, const char *executable, char *const argv[], char *const envp[]);

int fork_agent(const char *name, const int except[], size_t n_except, pid_t *ret_pid, const char *path, ...) _sentinel_;
