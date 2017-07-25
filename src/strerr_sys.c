/* Public domain. */

#include "error.h"
#include "strerr.h"

struct strerr strerr_sys;

void strerr_sysinit(void)
{
  strerr_sys.who = 0;
  strerr_sys.x = error_str(errno);
  strerr_sys.y = "";
  strerr_sys.z = "";
}
