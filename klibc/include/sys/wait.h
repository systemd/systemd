/*
 * sys/wait.h
 */

#ifndef _SYS_WAIT_H
#define _SYS_WAIT_H

#include <klibc/extern.h>
#include <sys/types.h>
#include <sys/resource.h>

#include <linux/wait.h>

#define WEXITSTATUS(s)	(((s) & 0xff00) >> 8)
#define WTERMSIG(s)	((s) & 0x7f)
#define WIFEXITED(s)	(WTERMSIG(s) == 0)
#define WIFSTOPPED(s)	(WTERMSIG(s) == 0x7f)
/* Ugly hack to avoid multiple evaluation of "s" */
#define WIFSIGNALED(s)	(WTERMSIG((s)+1) >= 2)
#define WCOREDUMP(s)	((s) & 0x80)
#define WSTOPSIG(s)	WEXITSTATUS(s)

__extern pid_t wait(int *);
__extern pid_t waitpid(pid_t, int *, int);
__extern pid_t wait3(int *, int, struct rusage *);
__extern pid_t wait4(pid_t, int *, int, struct rusage *);

#endif /* _SYS_WAIT_H */
