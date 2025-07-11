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
/* Defined since glibc-2.36.
 * Supported since kernel v5.2 (24dcb3d90a1f67fe08c68a004af37df059d74005). */
#if HAVE_FSOPEN
extern int fsopen(const char *__fs_name, unsigned int __flags) __THROW;
#else
int missing_fsopen(const char *fsname, unsigned flags);
#  define fsopen missing_fsopen
#endif

/* Create a mount representation for the FD created by fsopen using
   FLAGS with ATTR_FLAGS describing how the mount is to be performed.  */
/* Defined since glibc-2.36.
 * Supported since kernel v5.2 (93766fbd2696c2c4453dd8e1070977e9cd4e6b6d). */
#if HAVE_FSMOUNT
extern int fsmount(int __fd, unsigned int __flags, unsigned int __ms_flags) __THROW;
#else
int missing_fsmount(int fd, unsigned flags, unsigned ms_flags);
#  define fsmount missing_fsmount
#endif

/* Add the mounted FROM_DFD referenced by FROM_PATHNAME filesystem returned
   by fsmount in the hierarchy in the place TO_DFD reference by TO_PATHNAME
   using FLAGS.  */
/* Defined since glibc-2.36.
 * Supported since kernel v5.2 (2db154b3ea8e14b04fee23e3fdfd5e9d17fbc6ae). */
#if HAVE_MOVE_MOUNT
extern int move_mount(int __from_dfd, const char *__from_pathname, int __to_dfd, const char *__to_pathname, unsigned int flags) __THROW;
#else
int missing_move_mount(int from_dfd, const char *from_pathname, int to_dfd, const char *to_pathname, unsigned flags);
#  define move_mount missing_move_mount
#endif

/* Set parameters and trigger CMD action on the FD context.  KEY, VALUE,
   and AUX are used depending ng of the CMD.  */
/* Defined since glibc-2.36.
 * Supported since kernel v5.2 (ecdab150fddb42fe6a739335257949220033b782). */
#if HAVE_FSCONFIG
extern int fsconfig(int __fd, unsigned int __cmd, const char *__key, const void *__value, int __aux) __THROW;
#else
int missing_fsconfig(int fd, unsigned cmd, const char *key, const void *value, int aux);
#  define fsconfig missing_fsconfig
#endif

/* Open the mount point FILENAME in directory DFD using FLAGS.  */
/* Defined since glibc-2.36.
 * Supported since kernel v5.2 (a07b20004793d8926f78d63eb5980559f7813404). */
#if HAVE_OPEN_TREE
extern int open_tree(int __dfd, const char *__filename, unsigned int __flags) __THROW;
#else
int missing_open_tree(int dfd, const char *filename, unsigned flags);
#  define open_tree missing_open_tree
#endif

/* Change the mount properties of the mount or an entire mount tree.  If
   PATH is a relative pathname, then it is interpreted relative to the
   directory referred to by the file descriptor dirfd.  Otherwise if DFD is
   the special value AT_FDCWD then PATH is interpreted relative to the current
   working directory of the calling process.  */
/* Defined since glibc-2.36.
 * Supported since kernel v5.12 (2a1867219c7b27f928e2545782b86daaf9ad50bd). */
#if HAVE_MOUNT_SETATTR
extern int mount_setattr(int __dfd, const char *__path, unsigned int __flags, struct mount_attr *__uattr, size_t __usize) __THROW;
#else
int missing_mount_setattr(int dfd, const char *path, unsigned flags, struct mount_attr *attr, size_t size);
#  define mount_setattr missing_mount_setattr
#endif

/* Not defined in glibc yet as of glibc-2.41.
 * Supported since kernel v6.15 (c4a16820d90199409c9bf01c4f794e1e9e8d8fd8). */
#if HAVE_OPEN_TREE_ATTR
extern int open_tree_attr(int __dfd, const char *__filename, unsigned int __flags, struct mount_attr *__uattr, size_t __usize) __THROW;
#else
int missing_open_tree_attr(int dfd, const char *filename, unsigned int flags, struct mount_attr *attr, size_t size);
#  define open_tree_attr missing_open_tree_attr
#endif
