/*
 * sprintf.c
 */

#include <stdio.h>
#include <unistd.h>

int sprintf(char *buffer, const char *format, ...)
{
  va_list ap;
  int rv;

  va_start(ap, format);
  rv = vsnprintf(buffer, ~(size_t)0, format, ap);
  va_end(ap);

  return rv;
}
