/*
 * sys/vfs.h
 */

#ifndef _SYS_VFS_H
#define _SYS_VFS_H

#include <klibc/extern.h>
#include <linux/vfs.h>

__extern int statfs(const char *, struct statfs *);
__extern int fstatfs(int, struct statfs *);

#endif /* _SYS_VFS_H */
