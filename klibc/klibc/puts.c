/*
 * puts.c
 */

#include <stdio.h>

int puts(const char *s)
{
  if ( fputs(s, stdout) < 0 )
    return -1;

  return _fwrite("\n", 1, stdout);
}
