/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>
#include <sys/types.h>

#include "missing_pidfd.h"
#include "missing_syscall.h"

int pidfd_get_namespace(int fd, unsigned int ns_type_flag);

int pidfd_get_pid(int fd, pid_t *ret);
int pidfd_verify_pid(int pidfd, pid_t pid);
