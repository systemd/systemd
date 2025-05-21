/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <features.h>
#include <linux/mount.h> /* IWYU pragma: export */
#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "missing_fcntl.h"
#include "missing_fs.h"
#include "missing_syscall_def.h"

/* Possible value for FLAGS parameter of `umount2'.  */
enum
{
        MNT_FORCE = 1,                /* Force unmounting.  */
#define MNT_FORCE MNT_FORCE
        MNT_DETACH = 2,               /* Just detach from the tree.  */
#define MNT_DETACH MNT_DETACH
        MNT_EXPIRE = 4,               /* Mark for expiry.  */
#define MNT_EXPIRE MNT_EXPIRE
        UMOUNT_NOFOLLOW = 8           /* Don't follow symlink on umount.  */
#define UMOUNT_NOFOLLOW UMOUNT_NOFOLLOW
};

/* Mount a filesystem.  */
extern int mount(const char *__special_file, const char *__dir, const char *__fstype, unsigned long int __rwflag, const void *__data) __THROW;

/* Unmount a filesystem.  */
extern int umount(const char *__special_file) __THROW;

/* Unmount a filesystem.  Force unmounting if FLAGS is set to MNT_FORCE.  */
extern int umount2(const char *__special_file, int __flags) __THROW;

/* Open the filesystem referenced by FS_NAME so it can be configured for
   mouting.  */
#if HAVE_FSOPEN
extern int fsopen(const char *__fs_name, unsigned int __flags) __THROW;
#else
static inline int missing_fsopen(const char *fsname, unsigned flags) {
        return syscall(__NR_fsopen, fsname, flags);
}
#  define fsopen missing_fsopen
#endif

/* Create a mount representation for the FD created by fsopen using
   FLAGS with ATTR_FLAGS describing how the mount is to be performed.  */
#if HAVE_FSMOUNT
extern int fsmount(int __fd, unsigned int __flags, unsigned int __ms_flags) __THROW;
#else
static inline int missing_fsmount(int fd, unsigned flags, unsigned ms_flags) {
        return syscall(__NR_fsmount, fd, flags, ms_flags);
}
#  define fsmount missing_fsmount
#endif

/* Add the mounted FROM_DFD referenced by FROM_PATHNAME filesystem returned
   by fsmount in the hierarchy in the place TO_DFD reference by TO_PATHNAME
   using FLAGS.  */
#if HAVE_MOVE_MOUNT
extern int move_mount(int __from_dfd, const char *__from_pathname, int __to_dfd, const char *__to_pathname, unsigned int flags) __THROW;
#else
static inline int missing_move_mount(
                int from_dfd,
                const char *from_pathname,
                int to_dfd,
                const char *to_pathname,
                unsigned flags) {

        return syscall(__NR_move_mount, from_dfd, from_pathname, to_dfd, to_pathname, flags);
}
#  define move_mount missing_move_mount
#endif

/* Set parameters and trigger CMD action on the FD context.  KEY, VALUE,
   and AUX are used depending ng of the CMD.  */
#if HAVE_FSCONFIG
extern int fsconfig(int __fd, unsigned int __cmd, const char *__key, const void *__value, int __aux) __THROW;
#else
static inline int missing_fsconfig(int fd, unsigned cmd, const char *key, const void *value, int aux) {
        return syscall(__NR_fsconfig, fd, cmd, key, value, aux);
}
#  define fsconfig missing_fsconfig
#endif

/* Equivalent of fopen for an existing mount point.  */
#if HAVE_FSPICK
extern int fspick(int __dfd, const char *__path, unsigned int __flags) __THROW;
#endif

/* Open the mount point FILENAME in directory DFD using FLAGS.  */
#if HAVE_OPEN_TREE
extern int open_tree(int __dfd, const char *__filename, unsigned int __flags) __THROW;
#else
static inline int missing_open_tree(int dfd, const char *filename, unsigned flags) {
        return syscall(__NR_open_tree, dfd, filename, flags);
}
#  define open_tree missing_open_tree
#endif

/* Change the mount properties of the mount or an entire mount tree.  If
   PATH is a relative pathname, then it is interpreted relative to the
   directory referred to by the file descriptor dirfd.  Otherwise if DFD is
   the special value AT_FDCWD then PATH is interpreted relative to the current
   working directory of the calling process.  */
#if HAVE_MOUNT_SETATTR
extern int mount_setattr(int __dfd, const char *__path, unsigned int __flags, struct mount_attr *__uattr, size_t __usize) __THROW;
#else
static inline int missing_mount_setattr(int dfd, const char *path, unsigned flags, struct mount_attr *attr, size_t size) {
        return syscall(__NR_mount_setattr, dfd, path, flags, attr, size);
}
#  define mount_setattr missing_mount_setattr
#endif
