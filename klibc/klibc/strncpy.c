/*
 * strncpy.c
 */

#include <string.h>

char *strncpy(char *dst, const char *src, size_t n)
{
  char *q = dst;
  const char *p = src;
  char ch;

  while (n) {
    n--;
    *q++ = ch = *p++;
    if ( !ch )
      break;
  }

  /* The specs say strncpy() fills the entire buffer with NUL.  Sigh. */
  memset(q, 0, n);

  return dst;
}
