/*
 * __put_env.c - common code for putenv() and setenv()
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Initialized to zero, meaning "not malloc'd" */
static size_t __environ_size;

/* str should be a duplicated version of the input string;
   len is the length of the key including the = sign */
int __put_env(char *str, size_t len, int overwrite)
{
  char **p, *q;
  char **newenv;
  size_t n;

  n = 1;			/* Include space for final NULL */
  for ( p = environ ; (q = *p) ; p++ ) {
    n++;
    if ( !strncmp(q,str,len) ) {
      if ( !overwrite )
	free(str);
      else
	*p = str;		/* Possible memory leak... */
      return 0;
    }
  }

  /* Need to extend the environment */
  if ( n < __environ_size ) {
    p[1] = NULL;
    *p = str;
    return 0;
  } else {
    if ( __environ_size ) {
      newenv = realloc(environ, (__environ_size << 1)*sizeof(char *));
      if ( !newenv )
	return -1;

      __environ_size <<= 1;
    } else {
      /* Make a reasonable guess how much more space we need */
      size_t newsize = n+32;
      newenv = malloc(newsize*sizeof(char *));
      if ( !newenv )
	return -1;

      memcpy(newenv, environ, n*sizeof(char *));
      __environ_size = newsize;
    }
    newenv[n-1] = str;		/* Old NULL position */
    newenv[n]   = NULL;
    environ = newenv;
  }
  return 0;
}
