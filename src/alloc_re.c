/* Public domain. */

#include "alloc.h"
#include "byte.h"

int alloc_re(x,m,n)
char **x;
unsigned int m;
unsigned int n;
{
  char *y;
 
  y = alloc(n);
  if (!y) return 0;
  byte_copy(y,m,*x);
  alloc_free(*x);
  *x = y;
  return 1;
}
