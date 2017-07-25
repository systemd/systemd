/* Public domain. */

#include <fcntl.h>
#include "coe.h"

int coe(int fd)
{
  return fcntl(fd,F_SETFD,1);
}
