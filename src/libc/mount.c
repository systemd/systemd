/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>

#include "libc-shim.h"

DEFINE_SYSCALL_SHIM(fsopen, int,
                    const char *, fsname,
                    unsigned, flags)

DEFINE_SYSCALL_SHIM(fsmount, int,
                    int, fd,
                    unsigned, flags,
                    unsigned, ms_flags)

DEFINE_SYSCALL_SHIM(move_mount, int,
                    int, from_dfd,
                    const char *, from_pathname,
                    int, to_dfd,
                    const char *, to_pathname,
                    unsigned, flags)

DEFINE_SYSCALL_SHIM(fsconfig, int,
                    int, fd,
                    unsigned, cmd,
                    const char *, key,
                    const void *, value,
                    int, aux)

DEFINE_SYSCALL_SHIM(open_tree, int,
                    int, dfd,
                    const char *, filename,
                    unsigned, flags)

DEFINE_SYSCALL_SHIM(mount_setattr, int,
                    int, dfd,
                    const char *, path,
                    unsigned, flags,
                    struct mount_attr *, attr,
                    size_t, size)

DEFINE_SYSCALL_SHIM(open_tree_attr, int,
                    int, dfd,
                    const char *, filename,
                    unsigned int, flags,
                    struct mount_attr *, attr,
                    size_t, size)
