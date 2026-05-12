/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <spawn.h>

#include "libc-shim.h"

DEFINE_LIBC_SHIM(pidfd_spawn, int,
                 pid_t *restrict, pidfd,
                 const char *restrict, path,
                 const posix_spawn_file_actions_t *restrict, file_actions,
                 const posix_spawnattr_t *restrict, attrp,
                 char *const *restrict, argv,
                 char *const *restrict, envp)

DEFINE_LIBC_SHIM(posix_spawnattr_setcgroup_np, int,
                 posix_spawnattr_t *, attr,
                 int, cgroup)
