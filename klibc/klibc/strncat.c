/*
 * strncat.c
 */

#include <string.h>
#include <klibc/compiler.h>

char *strncat(char *dst, const char *src, size_t n)
{
  char *q = strchr(dst, '\0');
  const char *p = src;
  char ch;
  size_t nn = q-dst;

  if ( __likely(nn <= n) )
    n -= nn;

  while (n--) {
    *q++ = ch = *p++;
    if ( !ch )
      break;
  }

  return dst;
}
