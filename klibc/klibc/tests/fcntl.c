/*
 * Simple test of fcntl
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
  int fd = open(argv[0], O_RDONLY);
  struct flock l;
  long flags;

  (void)argc;

  if ( fd < 0 ) {
    perror("open");
    exit(1);
  }

  /* Get the flags on this FD */

  if ( (flags = fcntl(fd, F_GETFL)) == -1 ) {
    perror("F_GETFL");
    exit(1);
  }

  if ( flags != (O_RDONLY|O_LARGEFILE) )
    fprintf(stderr, "flags = %#lx\n", flags);

  /* Set a lock on this FD */
  memset(&l, 0, sizeof l);
  l.l_type   = F_RDLCK;
  l.l_whence = SEEK_SET;
  l.l_start  = 123;
  l.l_len    = 456;

  if ( fcntl(fd, F_SETLK, &l) == -1 ) {
    perror("F_SETLK");
    exit(1);
  }

  /* Eventually, fork and try to conflict with this lock... */

  return 0;
}

  
  
