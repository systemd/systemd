/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "missing_pidfd.h"      /* IWYU pragma: export */
#include "missing_syscall.h"    /* IWYU pragma: export */

int pidfd_get_namespace(int fd, unsigned long ns_type_cmd);

int pidfd_get_pid(int fd, pid_t *ret);
int pidfd_verify_pid(int pidfd, pid_t pid);

int pidfd_get_ppid(int fd, pid_t *ret);
int pidfd_get_uid(int fd, uid_t *ret);
int pidfd_get_cgroupid(int fd, uint64_t *ret);

int pidfd_get_inode_id_impl(int fd, uint64_t *ret);
int pidfd_get_inode_id(int fd, uint64_t *ret);
int pidfd_get_inode_id_self_cached(uint64_t *ret);

int pidfd_check_pidfs(int pid_fd);
