/*
 * exit.c
 *
 * Note: all programs need exit(), since it's invoked from
 * crt0.o.  Therefore there is no point in breaking apart
 * exit() and _exit().
 */

#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

/* We have an assembly version for i386 and x86-64 */

#if !defined(__i386__) && !defined(__x86_64__)

#define __NR___exit __NR_exit

/* Syscalls can't return void... */
static inline _syscall1(int,__exit,int,rv);

/* This allows atexit/on_exit to install a hook */
__noreturn (*__exit_handler)(int) = _exit;

__noreturn exit(int rv)
{
  __exit_handler(rv);
}

__noreturn _exit(int rv)
{
  __exit(rv);
  for(;;);
}

#endif
