/*
 * strlcpy.c
 */

#include <string.h>
#include <klibc/compiler.h>

size_t strlcpy(char *dst, const char *src, size_t size)
{
  size_t bytes = 0;
  char *q = dst;
  const char *p = src;
  char ch;

  while ( (ch = *p++) ) {
    if ( bytes < size )
      *q++ = ch;

    bytes++;
  }

  *q = '\0';
  return bytes;
}


