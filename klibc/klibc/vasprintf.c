/*
 * vasprintf.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

int vasprintf(char **bufp, const char *format, va_list ap)
{
  va_list ap1;
  int bytes;
  char *p;

  va_copy(ap1, ap);

  bytes = vsnprintf(NULL, 0, format, ap1) + 1;
  va_end(ap1);

  *bufp = p = malloc(bytes);
  if ( !p )
    return -1;
  
  return vsnprintf(p, bytes, format, ap);
}
