/* sbrk.c - Change data segment size */

/* Written 2000 by Werner Almesberger */
/* Modified 2003-2004 for klibc by H. Peter Anvin */

#include <stddef.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include "malloc.h"

char *__current_brk;		/* Common with brk.c */

/* p is an address,  a is alignment; must be a power of 2 */
static inline void *align_up(void *p, uintptr_t a)
{
  return (void *) (((uintptr_t)p + a-1) & ~(a-1));
}

void *sbrk(ptrdiff_t increment)
{
  char *start, *end, *new_brk;
  
  if (!__current_brk)
    __current_brk = __brk(NULL);

  start = align_up(__current_brk, SBRK_ALIGNMENT);
  end   = start + increment;

  new_brk = __brk(end);

  if (new_brk == (void *)-1)
    return (void *)-1;
  else if (new_brk < end) {
    errno = ENOMEM;
    return (void *) -1;
  }

  __current_brk = new_brk;
  return start;
}
