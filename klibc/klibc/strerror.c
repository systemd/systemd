/*
 * strerror.c
 */

#include <string.h>

char *strerror(int errnum)
{
  static char message[32] = "error "; /* enough for error 2^63-1 */
  char numbuf[32];
  char *p;
  unsigned int e = (unsigned int)errnum;

#ifdef WITH_ERRLIST
  extern const int sys_nerr;
  extern const char * const sys_errlist[];

  if ( e < (unsigned int)sys_nerr && sys_errlist[e] )
    return (char *)sys_errlist[e];
#endif

  p = numbuf+sizeof numbuf;
  *--p = '\0';

  do {
    *--p = (e % 10) + '0';
    e /= 10;
  } while ( e );

  memcpy(message+6, p, (numbuf+sizeof numbuf)-p);

  return message;
}

