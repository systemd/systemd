/* brk.c - Change data segment size */

/* Written 2000 by Werner Almesberger */


#include <stddef.h>
#include <unistd.h>
#include <sys/types.h>

char *__current_brk;		/* Common with sbrk.c */

/*
 * The Linux brk() isn't what most people expect, so we call the
 * system call __brk() and provide a wrapper.
 */
int brk(void *end_data_segment)
{
  char *new_brk;
  
  new_brk = __brk(end_data_segment);
  if (new_brk != end_data_segment) return -1;
  __current_brk = new_brk;
  return 0;
}
