/*
 * asprintf.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

int asprintf(char **bufp, const char *format, ...)
{
  va_list ap, ap1;
  int rv;
  int bytes;
  char *p;

  va_start(ap, format);
  va_copy(ap1, ap);

  bytes = vsnprintf(NULL, 0, format, ap1) + 1;
  va_end(ap1);

  *bufp = p = malloc(bytes);
  if ( !p )
    return -1;
  
  rv = vsnprintf(p, bytes, format, ap);
  va_end(ap);

  return rv;
}
