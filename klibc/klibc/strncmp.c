/*
 * strncmp.c
 */

#include <string.h>

int strncmp(const char *s1, const char *s2, size_t n)
{
  const unsigned char *c1 = s1, *c2 = s2;
  unsigned char ch;
  int d = 0;

  while ( n-- ) {
    d = (int)(ch = *c1++) - (int)*c2++;
    if ( d || !ch )
      break;
  }

  return d;
}
