/*
 * arch/s390/syscall.c
 *
 * Common error-handling path for system calls.
 * The return value from __syscall_common becomes the
 * return value from the system call.
 */
#include <errno.h>

long int __syscall_common(long int err)
{
	if ((unsigned long)(err) < (unsigned long)(-125))
		return err;
	errno = err;
	return -1;
}
