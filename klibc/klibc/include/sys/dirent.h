/*
 * sys/dirent.h
 */

#ifndef _SYS_DIRENT_H
#define _SYS_DIRENT_H

#include <sys/types.h>
#include <linux/dirent.h>

__extern int getdents(unsigned int, struct dirent *, unsigned int);

#endif /* _SYS_DIRENT_H */
