/*
 * vprintf.c
 */

#include <stdio.h>
#include <stdarg.h>

int vprintf(const char *format, va_list ap)
{
  return vfprintf(stdout, format, ap);
}
