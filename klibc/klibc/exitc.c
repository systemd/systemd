/*
 * exit.c
 *
 * Implement exit()
 */

#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

/* We have an assembly version for i386 and x86-64 */

#if !defined(__i386__) && !defined(__x86_64__)

/* This allows atexit/on_exit to install a hook */
__noreturn (*__exit_handler)(int) = _exit;

__noreturn exit(int rv)
{
  __exit_handler(rv);
}

#endif
