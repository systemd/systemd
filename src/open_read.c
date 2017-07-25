/* Public domain. */

#include <sys/types.h>
#include <fcntl.h>
#include "open.h"

int open_read(const char *fn)
{ return open(fn,O_RDONLY | O_NDELAY); }
