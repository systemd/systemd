/*
 * strchr.c
 */

#include <string.h>
#include <klibc/compiler.h>

char *strchr(const char *s, int c)
{
  while ( *s != (char)c ) {
    if ( ! *s )
      return NULL;
    s++;
  }

  return (char *)s;
}

__ALIAS(char *, index, (const char *, int), strchr)
