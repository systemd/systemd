/* Public domain. */

#include "stralloc.h"
#include "byte.h"

int stralloc_copyb(stralloc *sa,const char *s,unsigned int n)
{
  if (!stralloc_ready(sa,n + 1)) return 0;
  byte_copy(sa->s,n,s);
  sa->len = n;
  sa->s[n] = 'Z'; /* ``offensive programming'' */
  return 1;
}
