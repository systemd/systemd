/*
 * memmove.c
 */

#include <string.h>

void *memmove(void *dst, const void *src, size_t n)
{
  const char *p = src;
  char *q = dst;
#if defined(__i386__) || defined(__x86_64__)
  if ( q < p ) {
    asm volatile("cld ; rep ; movsb" : "+c" (n), "+S" (p), "+D" (q));
  } else {
    p += (n-1);
    q += (n-1);
    asm volatile("std ; rep ; movsb" : "+c" (n), "+S" (p), "+D" (q));
  }
#else
  if ( q < p ) {
    while ( n-- ) {
      *q++ = *p++;
    }
  } else {
    p += n;
    q += n;
    while ( n-- ) {
      *--q = *--p;
    }
  }
#endif

  return dst;
}
