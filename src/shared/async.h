/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "macro.h"
#include "rm-rf.h"

int asynchronous_job(void* (*func)(void *p), void *arg);

int asynchronous_sync(pid_t *ret_pid);
int asynchronous_close(int fd);
int asynchronous_rm_rf(const char *p, RemoveFlags flags);

DEFINE_TRIVIAL_CLEANUP_FUNC(int, asynchronous_close);
