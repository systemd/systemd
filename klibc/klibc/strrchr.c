/*
 * strrchr.c
 */

#include <string.h>

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
