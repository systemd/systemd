/*
 * strrchr.c
 */

#include <string.h>
#include <klibc/compiler.h>

char *strrchr(const char *s, int c)
{
  const char *found = NULL;
  
  while ( *s ) {
    if ( *s == (char) c )
      found = s;
    s++;
  }

  return (char *)found;
}

__ALIAS(char *, rindex, (const char *, int), strrchr)
