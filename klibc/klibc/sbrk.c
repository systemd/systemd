/* sbrk.c - Change data segment size */

/* Written 2000 by Werner Almesberger */

#include <stddef.h>
#include <unistd.h>
#include <sys/types.h>

char *__current_brk;		/* Common with brk.c */

void *sbrk(ptrdiff_t increment)
{
  char *old_brk, *new_brk;
  
  if (!__current_brk)
    __current_brk = __brk(NULL);
  new_brk = __brk(__current_brk+increment);
  if (new_brk != __current_brk+increment)
    return (void *) -1;
  old_brk = __current_brk;
  __current_brk = new_brk;
  return old_brk;
}
