/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <spawn.h>        /* IWYU pragma: export */

/* pidfd_spawn() and posix_spawnattr_setcgroup_np() were added in glibc 2.39. Redirect to shims that
 * return ENOSYS at runtime when the libc symbols aren't available, so callers don't need to worry
 * about the libc version. */
int pidfd_spawn_shim(pid_t *restrict pidfd, const char *restrict path,
                     const posix_spawn_file_actions_t *restrict file_actions,
                     const posix_spawnattr_t *restrict attrp,
                     char *const argv[restrict], char *const envp[restrict]);
#define pidfd_spawn pidfd_spawn_shim

int posix_spawnattr_setcgroup_np_shim(posix_spawnattr_t *attr, int cgroup);
#define posix_spawnattr_setcgroup_np posix_spawnattr_setcgroup_np_shim

/* Defined in <spawn.h> since glibc 2.39. */
#ifndef POSIX_SPAWN_SETCGROUP
#  define POSIX_SPAWN_SETCGROUP 0x100
#endif
