/* Public domain. */

#include "fmt.h"

unsigned int fmt_uint0(char *s,unsigned int u,unsigned int n)
{
  unsigned int len;
  len = fmt_uint(FMT_LEN,u);
  while (len < n) { if (s) *s++ = '0'; ++len; }
  if (s) fmt_uint(s,u);
  return len;
}
