/*
 * setenv.c
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Initialized to zero, meaning "not malloc'd" */
static size_t __environ_size;

/* str should be a duplicated version of the input string;
   len is the length of the key including the = sign */
static int _putenv(char *str, size_t len, int overwrite)
{
  char **p, *q;
  char **newenv;
  size_t n;

  n = 1;			/* Include space for final NULL */
  for ( p = environ ; (q = *p) ; p++ ) {
    n++;
    if ( !strncmp(q,str,len) ) {
      if ( overwrite )
	free(str);
      else
	*p = str;		/* Memory leak... */
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
    newenv[n+1] = NULL;
    newenv[n]   = str;
    environ = newenv;
  }
  return 0;
}

int putenv(const char *str)
{
  char *s;
  const char *e, *z;
  size_t len;

  if ( !str ) {
    errno = EINVAL;
    return -1;
  }

  len = 0; e = NULL;
  for ( z = str ; *z ; z++ ) {
    len++;
    if ( *z == '=' )
      e = z;
  }

  if ( !e ) {
    errno = EINVAL;
    return -1;
  }

  s = strdup(str);
  if ( !s )
    return -1;

  return _putenv(s, len, 1);
}

int setenv(const char *name, const char *val, int overwrite)
{
  const char *z;
  char *s;
  size_t l1, l2;

  if ( !name || !name[0] ) {
    errno = EINVAL;
    return -1;
  }

  l1 = 0;
  for ( z = name ; *z ; z++ ) {
    l1++;
    if ( *z == '=' ) {
      errno = EINVAL;
      return -1;
    }
  }

  l2 = strlen(val);

  s = malloc(l1+l2+2);
  if ( !s )
    return -1;

  memcpy(s, name, l1);
  s[l1] = '=';
  memcpy(s+l1+1, val, l2);
  s[l1+l2+1] = '\0';

  return _putenv(s, l1+1, overwrite);
}
