/*
 * memcpy.c
 */

#include <string.h>
#include <stdint.h>

void *memcpy(void *dst, const void *src, size_t n)
{
  const char *p = src;
  char *q = dst;
#if defined(__i386__)
  size_t nl = n >> 2;
  asm volatile("cld ; rep ; movsl ; movl %3,%0 ; rep ; movsb"
	       : "+c" (nl), "+S" (p), "+D" (q)
	       : "r" (n & 3));
#elif defined(__x86_64__)
  size_t nq = n >> 3;
  asm volatile("cld ; rep ; movsq ; movl %3,%%ecx ; rep ; movsb"
	       : "+c" (nq), "+S" (p), "+D" (q)
	       : "r" ((uint32_t)(n & 7)));
#else
  while ( n-- ) {
    *q++ = *p++;
  }
#endif

  return dst;
}
