/*
 * opendir/readdir/closedir
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/dirent.h>
#include <stdio.h>

#define __IO_DIR_DEFINED
struct _IO_dir {
  int fd;
  size_t bytes_left;
  struct dirent *next;
  struct dirent buffer[15];	/* 15 times max dirent size =~ 4K */
};

#include <dirent.h>

DIR *opendir(const char *name)
{
  DIR *dp = malloc(sizeof(DIR));

  if ( !dp )
    return NULL;

  dp->fd = open(name, O_DIRECTORY|O_RDONLY);

  if ( dp->fd < 0 ) {
    free(dp);
    return NULL;
  }

  dp->bytes_left = 0;

  return dp;
}

struct dirent *readdir(DIR *dir)
{
  struct dirent *dent;
  int rv;
  
  if ( !dir->bytes_left ) {
    rv = getdents(dir->fd, dir->buffer, sizeof(dir->buffer));
    if ( rv <= 0 )
      return NULL;
    dir->bytes_left = rv;
    dir->next = dir->buffer;
  }

  dent = dir->next;
  ((char *)dir->next) += dent->d_reclen;
  dir->bytes_left -= dent->d_reclen;
  
  return dent;
}

int closedir(DIR *dir)
{
  int rv;
  rv = close(dir->fd);
  free(dir);
  return rv;
}
