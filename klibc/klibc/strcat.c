/*
 * strcat.c
 */

#include <string.h>

char *strcat(char *dst, const char *src)
{
  strcpy(strchr(dst, '\0'), src);
  return dst;
}
