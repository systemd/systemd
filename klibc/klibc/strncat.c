/*
 * strncat.c
 */

#include <string.h>

char *strncat(char *dst, const char *src, size_t n)
{
  strncpy(strchr(dst, '\0'), src, n);
  return dst;
}
