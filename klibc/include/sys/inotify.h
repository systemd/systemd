/*
 * sys/inotify.h
 */

#ifndef _SYS_INOTIFY_H
#define _SYS_INOTIFY_H

#include <sys/types.h>
#include <linux/inotify.h>
#include <klibc/extern.h>

__extern int inotify_init(void);
__extern int inotify_add_watch(int, const char *, __u32);
__extern int inotify_rm_watch(int, __u32);

#endif /* _SYS_INOTIFY_H */
