/*
 * sys/fsuid.h
 */

#ifndef _SYS_FSUID_H
#define _SYS_FSUID_H

#include <klibc/extern.h>
#include <sys/types.h>

__extern int setfsuid(uid_t);
__extern int setfsgid(gid_t);

#endif /* _SYS_FSUID_H */
