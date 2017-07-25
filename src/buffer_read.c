/* Public domain. */

#include <unistd.h>
#include "buffer.h"

int buffer_unixread(int fd,char *buf,unsigned int len)
{
  return read(fd,buf,len);
}
