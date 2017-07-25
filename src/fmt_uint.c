/* Public domain. */

#include "fmt.h"

unsigned int fmt_uint(register char *s,register unsigned int u)
{
  return fmt_ulong(s,u);
}
