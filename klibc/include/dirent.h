/*
 * dirent.h
 */

#ifndef _DIRENT_H
#define _DIRENT_H

#include <klibc/extern.h>
#include <sys/dirent.h>

struct _IO_dir {
  int __fd;

#ifdef __KLIBC_DIRENT_INTERNALS
  /* These fields for internal use only */

  size_t bytes_left;
  struct dirent *next;
  /* Declaring this as an array of struct enforces correct alignment */
  struct dirent buffer[15];     /* 15 times max dirent size =~ 4K */
#endif
};
typedef struct _IO_dir DIR;

__extern DIR *opendir(const char *);
__extern struct dirent *readdir(DIR *);
__extern int closedir(DIR *);
static __inline__ int dirfd (DIR *__d) {
  return __d->__fd;
}

#endif /* _DIRENT_H */
