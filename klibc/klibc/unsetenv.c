/*
 * unsetenv.c
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int unsetenv(const char *name)
{
  size_t len;
  char **p, *q;
  const char *z;

  if ( !name || !name[0] ) {
    errno = EINVAL;
    return -1;
  }

  len = 0;
  for ( z = name ; *z ; z++ ) {
    len++;
    if ( *z == '=' ) {
      errno = EINVAL;
      return -1;
    }
  }

  for ( p = environ ; (q = *p) ; p++ ) {
    if ( !strncmp(name,q,len) && q[len] == '=' )
      break;
  }

  for ( ; (q = *p) ; p++ ) {
    p[0] = p[1];
  }

  return 0;
}
