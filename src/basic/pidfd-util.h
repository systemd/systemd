/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>
#if HAVE_PIDFD_OPEN
#include <sys/pidfd.h>
#endif
#include <sys/types.h>

int pidfd_get_pid(int fd, pid_t *ret);
int pidfd_verify_pid(int pidfd, pid_t pid);

int pidfd_get_cgroupid(int fd, uint64_t *ret);

int pidfd_get_inode_id(int fd, uint64_t *ret);
