/*
 * strtok.c
 */

#include <string.h>

char *strtok(char *s, const char *delim)
{
  static char *holder;

  if ( s )
    holder = s;

  return strsep(&holder, delim);
}

