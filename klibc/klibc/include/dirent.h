/*
 * dirent.h
 */

#ifndef _DIRENT_H
#define _DIRENT_H

#include <klibc/extern.h>
#include <sys/dirent.h>

#ifndef __IO_DIR_DEFINED
struct _IO_dir;
#endif
typedef struct _IO_dir DIR;

__extern DIR *opendir(const char *);
__extern struct dirent *readdir(DIR *);
__extern int closedir(DIR *);

#endif /* _DIRENT_H */
