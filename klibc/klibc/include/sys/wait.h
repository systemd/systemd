/*
 * sys/wait.h
 */

#ifndef _SYS_WAIT_H
#define _SYS_WAIT_H

#include <klibc/extern.h>
#include <sys/types.h>
#include <sys/resource.h>

#include <linux/wait.h>

__extern pid_t wait(int *);
__extern pid_t waitpid(pid_t, int *, int);
__extern pid_t wait3(int *, int, struct rusage *);
__extern pid_t wait4(pid_t, int *, int, struct rusage *);

#endif /* _SYS_WAIT_H */
