/*
 * arch/ppc64/syscall.c
 *
 * Common error-handling path for system calls.
 * The return value from __syscall_error becomes the
 * return value from the system call.
 */
#include <errno.h>

long int __syscall_error(long int err)
{
	errno = err;
	return -1;
}
