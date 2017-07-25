/* Public domain. */

#include "error.h"
#include "open.h"
#include "readclose.h"
#include "openreadclose.h"

int openreadclose(const char *fn,stralloc *sa,unsigned int bufsize)
{
  int fd;
  fd = open_read(fn);
  if (fd == -1) {
    if (errno == error_noent) return 0;
    return -1;
  }
  if (readclose(fd,sa,bufsize) == -1) return -1;
  return 1;
}
