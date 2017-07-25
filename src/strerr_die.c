/* Public domain. */

#include <unistd.h>
#include "buffer.h"
#include "strerr.h"

void strerr_warn(const char *x1,const char *x2,const char *x3,const char *x4,const char *x5,const char *x6,const struct strerr *se)
{
  strerr_sysinit();
 
  if (x1) buffer_puts(buffer_2,x1);
  if (x2) buffer_puts(buffer_2,x2);
  if (x3) buffer_puts(buffer_2,x3);
  if (x4) buffer_puts(buffer_2,x4);
  if (x5) buffer_puts(buffer_2,x5);
  if (x6) buffer_puts(buffer_2,x6);
 
  while(se) {
    if (se->x) buffer_puts(buffer_2,se->x);
    if (se->y) buffer_puts(buffer_2,se->y);
    if (se->z) buffer_puts(buffer_2,se->z);
    se = se->who;
  }
 
  buffer_puts(buffer_2,"\n");
  buffer_flush(buffer_2);
}

void strerr_die(int e,const char *x1,const char *x2,const char *x3,const char *x4,const char *x5,const char *x6,const struct strerr *se)
{
  strerr_warn(x1,x2,x3,x4,x5,x6,se);
  _exit(e);
}
