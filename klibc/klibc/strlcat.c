/*
 * strlcat.c
 */

#include <string.h>
#include <klibc/compiler.h>

size_t strlcat(char *dst, const char *src, size_t size)
{
  size_t bytes = 0;
  char *q = dst;
  const char *p = src;
  char ch;

  while ( bytes < size && *q ) {
    q++;
    bytes++;
  }
  if (bytes == size)
    return (bytes + strlen(src));

  while ( (ch = *p++) ) {
    if ( bytes+1 < size )
      *q++ = ch;

    bytes++;
  }

  *q = '\0';
  return bytes;
}


