#include <unistd.h>
#include <sys/syscall.h>

#ifdef __NR__newselect
#undef __NR_select
#define __NR_select __NR__newselect
#endif

_syscall5(int,select,int,a0,fd_set *,a1,fd_set *,a2,fd_set *,a3,struct timeval *,a4);
