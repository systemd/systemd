/*
 * getenv.c
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *getenv(const char *name)
{
  char **p, *q;
  int len = strlen(name);

  for ( p = environ ; (q = *p) ; p++ ) {
    if ( !strncmp(name, q, len) && q[len] == '=' ) {
      return q+(len+1);
    }
  }

  return NULL;
}

