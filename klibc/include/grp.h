/*
 * grp.h
 */

#ifndef _GRP_H
#define _GRP_H

#include <klibc/extern.h>
#include <sys/types.h>

__extern int setgroups(size_t, const gid_t *);

#endif /* _GRP_H */
