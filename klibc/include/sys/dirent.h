/*
 * sys/dirent.h
 */

#ifndef _SYS_DIRENT_H
#define _SYS_DIRENT_H

#include <stdint.h>

/* The kernel calls this struct dirent64 */
struct dirent {
  uint64_t		d_ino;
  int64_t		d_off;
  unsigned short	d_reclen;
  unsigned char		d_type;
  char			d_name[256];
};

__extern int getdents(unsigned int, struct dirent *, unsigned int);

#endif /* _SYS_DIRENT_H */
