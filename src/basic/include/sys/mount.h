/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fcntl.h>
#include <features.h>
#include <linux/fs.h>
#include <linux/mount.h> /* IWYU pragma: export */
#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>

/* Since glibc-2.37 (774058d72942249f71d74e7f2b639f77184160a6), sys/mount.h includes linux/mount.h, and
 * we can safely include both headers in the same source file. However, we cannot do that with older glibc.
 * To avoid conflicts, let's not use glibc's sys/mount.h, and provide our own minimal implementation.
 * Fortunately, most of definitions we need are covered by linux/fs.h and linux/mount.h, so only one enum
 * and a few function prototypes need to be defined here. */

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
/* since glibc-2.36 */
extern int fsopen(const char *__fs_name, unsigned int __flags) __THROW;
#else
int fsopen(const char *__fs_name, unsigned int __flags);
#endif

/* Create a mount representation for the FD created by fsopen using
   FLAGS with ATTR_FLAGS describing how the mount is to be performed.  */
#if HAVE_FSMOUNT
/* since glibc-2.36 */
extern int fsmount(int __fd, unsigned int __flags, unsigned int __ms_flags) __THROW;
#else
int fsmount(int __fd, unsigned int __flags, unsigned int __ms_flags);
#endif

/* Add the mounted FROM_DFD referenced by FROM_PATHNAME filesystem returned
   by fsmount in the hierarchy in the place TO_DFD reference by TO_PATHNAME
   using FLAGS.  */
#if HAVE_MOVE_MOUNT
/* since glibc-2.36 */
extern int move_mount(int __from_dfd, const char *__from_pathname, int __to_dfd, const char *__to_pathname, unsigned int flags) __THROW;
#else
int move_mount(int __from_dfd, const char *__from_pathname, int __to_dfd, const char *__to_pathname, unsigned int flags);
#endif

/* Set parameters and trigger CMD action on the FD context.  KEY, VALUE,
   and AUX are used depending ng of the CMD.  */
#if HAVE_FSCONFIG
/* since glibc-2.36 */
extern int fsconfig(int __fd, unsigned int __cmd, const char *__key, const void *__value, int __aux) __THROW;
#else
int fsconfig(int __fd, unsigned int __cmd, const char *__key, const void *__value, int __aux);
#endif

/* Open the mount point FILENAME in directory DFD using FLAGS.  */
#if HAVE_OPEN_TREE
/* since glibc-2.36 */
extern int open_tree(int __dfd, const char *__filename, unsigned int __flags) __THROW;
#else
int open_tree(int __dfd, const char *__filename, unsigned int __flags);
#endif

/* Change the mount properties of the mount or an entire mount tree.  If
   PATH is a relative pathname, then it is interpreted relative to the
   directory referred to by the file descriptor dirfd.  Otherwise if DFD is
   the special value AT_FDCWD then PATH is interpreted relative to the current
   working directory of the calling process.  */
#if HAVE_MOUNT_SETATTR
/* since glibc-2.36 */
extern int mount_setattr(int __dfd, const char *__path, unsigned int __flags, struct mount_attr *__uattr, size_t __usize) __THROW;
#else
int mount_setattr(int __dfd, const char *__path, unsigned int __flags, struct mount_attr *__attr, size_t __size);
#endif
