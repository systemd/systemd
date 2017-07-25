/* Public domain. */

#include "stralloc.h"
#include "byte.h"

int stralloc_catb(stralloc *sa,const char *s,unsigned int n)
{
  if (!sa->s) return stralloc_copyb(sa,s,n);
  if (!stralloc_readyplus(sa,n + 1)) return 0;
  byte_copy(sa->s + sa->len,n,s);
  sa->len += n;
  sa->s[sa->len] = 'Z'; /* ``offensive programming'' */
  return 1;
}
