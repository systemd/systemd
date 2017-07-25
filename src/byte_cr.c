/* Public domain. */

#include "byte.h"

void byte_copyr(to,n,from)
register char *to;
register unsigned int n;
register char *from;
{
  to += n;
  from += n;
  for (;;) {
    if (!n) return; *--to = *--from; --n;
    if (!n) return; *--to = *--from; --n;
    if (!n) return; *--to = *--from; --n;
    if (!n) return; *--to = *--from; --n;
  }
}
