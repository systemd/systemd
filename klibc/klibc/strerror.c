/*
 * strerror.c
 */

#include <string.h>

char *strerror(int errnum)
{
  static char message[32] = "error "; /* enough for error 2^63-1 */

  char numbuf[32];
  char *p;
  int len;

  p = numbuf+sizeof numbuf;
  *--p = '\0';

  do {
    *--p = (errnum % 10) + '0';
    errnum /= 10;
  } while ( errnum );

  return (char *)memcpy(message+6, p, (numbuf+sizeof numbuf)-p);
}

