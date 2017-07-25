/* Public domain. */

#include <unistd.h>
#include "fd.h"

int fd_move(int to,int from)
{
  if (to == from) return 0;
  if (fd_copy(to,from) == -1) return -1;
  close(from);
  return 0;
}
