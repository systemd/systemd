/*
 * onexit.c
 */

#include <stdlib.h>
#include <unistd.h>
#include "atexit.h"

extern __noreturn (*__exit_handler)(int);
static struct atexit *__atexit_list;

static __noreturn on_exit_exit(int rv)
{
  struct atexit *ap;
  
  for ( ap = __atexit_list ; ap ; ap = ap->next ) {
    ap->fctn(rv, ap->arg);	/* This assumes extra args are harmless */
  }
  
  _exit(rv);
}

int on_exit(void (*fctn)(int, void *), void *arg)
{
  struct atexit *as = malloc(sizeof(struct atexit));

  if ( !as )
    return -1;

  as->fctn = fctn;
  as->arg  = arg;

  as->next = __atexit_list;
  __atexit_list = as;

  __exit_handler = on_exit_exit;

  return 0;
}
