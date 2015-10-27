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

#include <stdbool.h>
#include <sys/types.h>
#include <alloca.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "formats-util.h"
#include "macro.h"

#define procfs_file_alloca(pid, field)                                  \
        ({                                                              \
                pid_t _pid_ = (pid);                                    \
                const char *_r_;                                        \
                if (_pid_ == 0) {                                       \
                        _r_ = ("/proc/self/" field);                    \
                } else {                                                \
                        _r_ = alloca(strlen("/proc/") + DECIMAL_STR_MAX(pid_t) + 1 + sizeof(field)); \
                        sprintf((char*) _r_, "/proc/"PID_FMT"/" field, _pid_);                       \
                }                                                       \
                _r_;                                                    \
        })

int get_process_state(pid_t pid);
int get_process_comm(pid_t pid, char **name);
int get_process_cmdline(pid_t pid, size_t max_length, bool comm_fallback, char **line);
int get_process_exe(pid_t pid, char **name);
int get_process_uid(pid_t pid, uid_t *uid);
int get_process_gid(pid_t pid, gid_t *gid);
int get_process_capeff(pid_t pid, char **capeff);
int get_process_cwd(pid_t pid, char **cwd);
int get_process_root(pid_t pid, char **root);
int get_process_environ(pid_t pid, char **environ);
int get_process_ppid(pid_t pid, pid_t *ppid);

int wait_for_terminate(pid_t pid, siginfo_t *status);
int wait_for_terminate_and_warn(const char *name, pid_t pid, bool check_exit_code);

void sigkill_wait(pid_t *pid);
#define _cleanup_sigkill_wait_ _cleanup_(sigkill_wait)

int kill_and_sigcont(pid_t pid, int sig);

void rename_process(const char name[8]);
int is_kernel_thread(pid_t pid);

int getenv_for_pid(pid_t pid, const char *field, char **_value);

bool pid_is_alive(pid_t pid);
bool pid_is_unwaited(pid_t pid);

bool is_main_thread(void);

noreturn void freeze(void);

bool oom_score_adjust_is_valid(int oa);

#ifndef PERSONALITY_INVALID
/* personality(7) documents that 0xffffffffUL is used for querying the
 * current personality, hence let's use that here as error
 * indicator. */
#define PERSONALITY_INVALID 0xffffffffLU
#endif

unsigned long personality_from_string(const char *p);
const char *personality_to_string(unsigned long);

int ioprio_class_to_string_alloc(int i, char **s);
int ioprio_class_from_string(const char *s);

const char *sigchld_code_to_string(int i) _const_;
int sigchld_code_from_string(const char *s) _pure_;

int sched_policy_to_string_alloc(int i, char **s);
int sched_policy_from_string(const char *s);

#define PTR_TO_PID(p) ((pid_t) ((uintptr_t) p))
#define PID_TO_PTR(p) ((void*) ((uintptr_t) p))
